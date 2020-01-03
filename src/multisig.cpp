// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <alloca.h>
#include <memory>

#if defined(_MSC_VER)
#include <malloc.h>
#endif

#include "Varint.h"
#include "multisig.h"
#include "random.h"

namespace Crypto
{
    namespace Multisig
    {
        extern "C"
        {
#include "crypto-ops.h"
#include "keccak.h"
        }

        /* Checks if an arbitrary pod is a scalar */
        template<typename T> bool is_scalar(const T &key)
        {
            return !sc_check(reinterpret_cast<const unsigned char *>(key.data));
        }

        /* Used to sort a vector of keys so that they are always
           in the same order */
        template<typename T> void sortKeys(std::vector<T> &keys)
        {
            std::sort(keys.begin(), keys.end(), [](const T &a, const T &b) { return memcmp(&a, &b, sizeof(a)); });
        };

        template<typename T> void addKeys(const T &a, const T &b, T &c)
        {
            if (!is_scalar(a))
            {
                ge_p3 b2;
                ge_p3 a2;
                ge_frombytes_vartime(&b2, reinterpret_cast<const unsigned char *>(b.data));
                ge_frombytes_vartime(&a2, reinterpret_cast<const unsigned char *>(a.data));
                ge_cached tmp2;
                ge_p3_to_cached(&tmp2, &b2);
                ge_p1p1 tmp3;
                ge_add(&tmp3, &a2, &tmp2);
                ge_p1p1_to_p3(&a2, &tmp3);
                ge_p3_tobytes(reinterpret_cast<unsigned char *>(c.data), &a2);
            }
            else
            {
                sc_add(
                    reinterpret_cast<unsigned char *>(&c),
                    reinterpret_cast<const unsigned char *>(&a),
                    reinterpret_cast<const unsigned char *>(&b));
            }
        };

        template<typename T> T addKeys(const std::vector<T> &keys)
        {
            if (keys.size() == 0)
            {
                return T();
            }
            else if (keys.size() == 1)
            {
                return keys.front();
            }

            T result = keys.front();

            for (size_t i = 1; i < keys.size(); i++)
            {
                addKeys(result, keys.at(i), result);
            }

            return result;
        };

        template<typename T> T addKeys(const T &key, const std::vector<T> &keys)
        {
            std::vector<T> _keys;

            _keys.push_back(key);

            for (const auto &_key : keys)
            {
                _keys.push_back(_key);
            }

            return addKeys(_keys);
        };

        /* Public Methods */
        void generate_n_n(
            const Crypto::PublicKey &ourPublicSpendKey,
            const Crypto::SecretKey &ourPrivateViewKey,
            const std::vector<Crypto::PublicKey> &publicSpendKeys,
            const std::vector<Crypto::SecretKey> &secretSpendKeys,
            Crypto::PublicKey &sharedPublicSpendKey,
            Crypto::SecretKey &sharedPrivateViewKey)
        {
            sharedPublicSpendKey = addKeys(ourPublicSpendKey, publicSpendKeys);

            sharedPrivateViewKey = addKeys(ourPrivateViewKey, secretSpendKeys);
        }

        Crypto::SecretKey
            generate_partial_signing_key(const Crypto::Signature &signature, const Crypto::SecretKey &privateSpendKey)
        {
            const Crypto::SecretKey signatureAsKey(signature.data);

            Crypto::SecretKey result;

            sc_mul(
                reinterpret_cast<unsigned char *>(&result),
                reinterpret_cast<const unsigned char *>(&signatureAsKey),
                reinterpret_cast<const unsigned char *>(&privateSpendKey));

            return result;
        }

        Crypto::KeyImage restore_key_image(
            const Crypto::PublicKey &publicEphemeral,
            const Crypto::EllipticCurveScalar &derivationScalar,
            const std::vector<Crypto::KeyImage> &partialKeyImages)
        {
            Crypto::SecretKey _derivation(derivationScalar.data);

            Crypto::KeyImage baseKeyImage;

            Crypto::generate_key_image(publicEphemeral, _derivation, baseKeyImage);

            return addKeys(baseKeyImage, partialKeyImages);
        }

        Crypto::KeyImage restore_key_image(
            const Crypto::PublicKey &publicEphemeral,
            const Crypto::KeyDerivation &derivation,
            const size_t output_index,
            const std::vector<Crypto::KeyImage> &partialKeyImages)
        {
            Crypto::EllipticCurveScalar _derivationScalar;

            Crypto::derivation_to_scalar(derivation, output_index, _derivationScalar);

            return restore_key_image(publicEphemeral, _derivationScalar, partialKeyImages);
        }

        bool restore_ring_signatures(
            const Crypto::EllipticCurveScalar &derivationScalar,
            const std::vector<Crypto::SecretKey> &partialSigningKeys,
            const uint64_t realOutput,
            const Crypto::EllipticCurveScalar &k,
            std::vector<Crypto::Signature> &signatures)
        {
            Crypto::SecretKey _derivation(derivationScalar.data);

            Crypto::SecretKey _partialKey = generate_partial_signing_key(signatures[realOutput], _derivation);

            Crypto::SecretKey derivedSecretKey = addKeys(_partialKey, partialSigningKeys);

            sc_sub(
                reinterpret_cast<unsigned char *>(&signatures[realOutput]) + 32,
                reinterpret_cast<const unsigned char *>(&k),
                reinterpret_cast<const unsigned char *>(&derivedSecretKey));

            return true;
        }

        bool restore_ring_signatures(
            const Crypto::KeyDerivation &derivation,
            const size_t output_index,
            const std::vector<Crypto::SecretKey> &partialSigningKeys,
            const uint64_t realOutput,
            const Crypto::EllipticCurveScalar &k,
            std::vector<Crypto::Signature> &signatures)
        {
            Crypto::EllipticCurveScalar _derivationScalar;

            Crypto::derivation_to_scalar(derivation, output_index, _derivationScalar);

            return restore_ring_signatures(_derivationScalar, partialSigningKeys, realOutput, k, signatures);
        }

        uint32_t rounds_required(const uint32_t participants, uint32_t threshold)
        {
            return participants - threshold + 1;
        }
    } // namespace Multisig
} // namespace Crypto