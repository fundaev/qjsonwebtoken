/*
   Copyright (c) 2016 Sergei Fundaev

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software
   is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included
   in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
   IN THE SOFTWARE.
*/


#include <QMessageAuthenticationCode>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include "JsonWebToken.h"

namespace
{
    const char TokenSeparator = '.';
    const QString KeyAlgorithm = "alg";
    const QString KeyType = "typ";
    const QString TypeJwt = "JWT";


    QByteArray base64encode(const QByteArray &data)
    {
        return data.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    }

    QByteArray base64decode(const QByteArray &data)
    {
        return QByteArray::fromBase64(data, QByteArray::Base64UrlEncoding);
    }

    QByteArray makeJson(const QJsonObject &object)
    {
        QJsonDocument doc;
        doc.setObject(object);
        return doc.toJson(QJsonDocument::Compact);
    }

    QJsonObject parseJson(const QByteArray &data, bool &ok)
    {
        ok = false;
        QJsonParseError error;
        QJsonDocument doc = QJsonDocument::fromJson(data, &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject())
            return QJsonObject();

        ok = true;
        return doc.object();
    }
}

JsonWebToken::JsonWebToken()
    : m_algorithm(None)
{
}

JsonWebToken::JsonWebToken(Algorithm algorithm, const QByteArray &key)
    : m_algorithm(algorithm),
      m_key(key)
{
}

void JsonWebToken::setAlgorithm(JsonWebToken::Algorithm algorithm)
{
    m_algorithm = algorithm;
}

JsonWebToken::Algorithm JsonWebToken::algorithm() const
{
    return m_algorithm;
}

void JsonWebToken::setKey(const QByteArray &key)
{
    m_key = key;
}

QByteArray JsonWebToken::key() const
{
    return m_key;
}

void JsonWebToken::addClaim(const QString &name, const QJsonValue &value)
{
    m_claims.insert(name, value);
}

QJsonValue JsonWebToken::claim(const QString &name) const
{
    return m_claims.value(name);
}

QStringList JsonWebToken::claims() const
{
    return m_claims.keys();
}

bool JsonWebToken::contains(const QString &name) const
{
    return m_claims.contains(name);
}

QByteArray JsonWebToken::encode() const
{
    QJsonObject header;
    header.insert(KeyAlgorithm, algorithmName());
    header.insert(KeyType, TypeJwt);
    QByteArray data = base64encode(makeJson(header));
    data.append(TokenSeparator).append(base64encode(makeJson(m_claims)));
    QByteArray signature = base64encode(encrypt(data));
    data.append(TokenSeparator).append(signature);

    return data;
}

bool JsonWebToken::decode(const QByteArray &token)
{
    m_claims = QJsonObject();
    int pos1 = token.indexOf(TokenSeparator);
    if (pos1 == -1)
        return false;

    int pos2 = token.indexOf(TokenSeparator, pos1 + 1);
    if (pos2 == -1)
        return false;

    QByteArray header = token.left(pos1);
    QByteArray payload = token.mid(pos1 + 1, pos2 - pos1 - 1);
    QByteArray signature = token.right(token.length() - pos2 - 1);

    if (!decodeHeader(header))
        return false;

    if (!decodePayload(payload))
        return false;

    return validate(token.left(pos2), signature);
}

QByteArray JsonWebToken::encrypt(const QByteArray &data) const
{
    if (m_algorithm == Hs256)
        return QMessageAuthenticationCode::hash(data, m_key, QCryptographicHash::Sha256);

    if (m_algorithm == Hs384)
        return QMessageAuthenticationCode::hash(data, m_key, QCryptographicHash::Sha384);

    if (m_algorithm == Hs512)
        return QMessageAuthenticationCode::hash(data, m_key, QCryptographicHash::Sha512);

    return QByteArray();
}

bool JsonWebToken::decodeHeader(const QByteArray &data)
{
    bool ok = false;
    QJsonObject header = parseJson(base64decode(data), ok);
    if (!ok)
        return false;

    if (!header.contains(KeyType) || header.value(KeyType).toString() != TypeJwt)
        return false;

    if (!header.contains(KeyAlgorithm) || !setAlgorithmByName(header.value(KeyAlgorithm).toString()))
        return false;

    return true;
}

bool JsonWebToken::decodePayload(const QByteArray &data)
{
    bool ok = false;
    m_claims = parseJson(base64decode(data), ok);
    return ok;
}

bool JsonWebToken::validate(const QByteArray &data, const QByteArray &signature)
{
    return (base64encode(encrypt(data)) == signature);
}

QString JsonWebToken::algorithmName() const
{
    switch (m_algorithm)
    {
    case Hs256:
        return "HS256";
    case Hs384:
        return "HS384";
    case Hs512:
        return "HS512";
    default:
        break;
    }

    return "none";
}

bool JsonWebToken::setAlgorithmByName(const QString &name)
{
    if (name == "HS256")
    {
        m_algorithm = Hs256;
        return true;
    }

    if (name == "HS384")
    {
        m_algorithm = Hs384;
        return true;
    }

    if (name == "HS512")
    {
        m_algorithm = Hs512;
        return true;
    }

    if (name == "none")
    {
        m_algorithm = None;
        return true;
    }

    return false;
}
