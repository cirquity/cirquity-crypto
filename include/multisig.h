// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.
#pragma once

#include "crypto.h"

#include <iostream>

namespace Crypto
{
    namespace Multisig
    {
        /* Generates the keys required for a N:N wallet by adding
           the private view keys and public spend keys together */
        void generate_n_n(
            const Crypto::PublicKey &ourPublicSpendKey,
            const Crypto::SecretKey &ourPrivateViewKey,
            const std::vector<Crypto::PublicKey> &publicSpendKeys,
            const std::vector<Crypto::SecretKey> &secretSpendKeys,
            Crypto::PublicKey &sharedPublicSpendKey,
            Crypto::SecretKey &sharedPrivateViewKey);

        /* Generates the the partial ring signing key using
           the base signature and our private spend key */
        Crypto::SecretKey
            generate_partial_signing_key(const Crypto::Signature &signature, const Crypto::SecretKey &privateSpendKey);

        /* Used to restore a key image using the partial
           keyImages supplied by other participants */
        Crypto::KeyImage restore_key_image(
            const Crypto::PublicKey &publicEphemeral,
            const Crypto::EllipticCurveScalar &derivationScalar,
            const std::vector<Crypto::KeyImage> &partialKeyImages);
        Crypto::KeyImage restore_key_image(
            const Crypto::PublicKey &publicEphemeral,
            const Crypto::KeyDerivation &derivation,
            const size_t output_index,
            const std::vector<Crypto::KeyImage> &partialKeyImages);

        /* Completes the ring signatures once enough parts
           have been collected to do so */
        bool restore_ring_signatures(
            const Crypto::EllipticCurveScalar &derivationScalar,
            const std::vector<Crypto::SecretKey> &partialSigningKeys,
            const uint64_t realOutput,
            const Crypto::EllipticCurveScalar &k,
            std::vector<Crypto::Signature> &signatures);
        bool restore_ring_signatures(
            const Crypto::KeyDerivation &derivation,
            const size_t output_index,
            const std::vector<Crypto::SecretKey> &partialSigningKeys,
            const uint64_t realOutput,
            const Crypto::EllipticCurveScalar &k,
            std::vector<Crypto::Signature> &signatures);

        /* Calculates the number of multisig rounds required for anything other than N:N */
        uint32_t rounds_required(const uint32_t participants, uint32_t threshold);
    } // namespace Multisig
} // namespace Crypto