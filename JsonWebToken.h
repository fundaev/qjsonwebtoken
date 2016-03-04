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

#ifndef JSONWEBTOKEN_H
#define JSONWEBTOKEN_H

#include <QByteArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QStringList>

class JsonWebToken
{
public:
    enum Algorithm
    {
        None,
        Hs256,
        Hs384,
        Hs512
    };

    JsonWebToken();
    JsonWebToken(Algorithm algorithm, const QByteArray &key);
    void setAlgorithm(Algorithm algorithm);
    Algorithm algorithm() const;
    void setKey(const QByteArray &key);
    QByteArray key() const;
    void addClaim(const QString &name, const QJsonValue &value);
    QJsonValue claim(const QString &name) const;
    QStringList claims() const;
    bool contains(const QString &name) const;
    QByteArray encode() const;
    bool decode(const QByteArray &token);

private:
    QByteArray encrypt(const QByteArray &data) const;
    bool decodeHeader(const QByteArray &data);
    bool decodePayload(const QByteArray &data);
    bool validate(const QByteArray &data, const QByteArray &signature);
    QString algorithmName() const;
    bool setAlgorithmByName(const QString &name);

private:
    Algorithm m_algorithm;
    QByteArray m_key;
    QJsonObject m_claims;
};

#endif // JSONWEBTOKEN_H
