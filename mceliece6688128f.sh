#!/bin/sh
#       $OpenBSD: $

# Copyright (c) 2023-2025 Simon Josefsson.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Based on public domain sntrup761.sh.

LICENSE="libmceliece-20241009/doc/license.md"
PEOPLE="libmceliece-20241009/doc/people.md"
FILES="	libmceliece-20241009/include-build/crypto_declassify.h
	libmceliece-20241009/crypto_kem/6688128f/vec/params.h
	libmceliece-20241009/cryptoint/crypto_int8.h
	libmceliece-20241009/cryptoint/crypto_int16.h
	libmceliece-20241009/cryptoint/crypto_int32.h
	libmceliece-20241009/cryptoint/crypto_int64.h
	libmceliece-20241009/cryptoint/crypto_uint8.h
	libmceliece-20241009/cryptoint/crypto_uint16.h
	libmceliece-20241009/cryptoint/crypto_uint32.h
	libmceliece-20241009/cryptoint/crypto_uint64.h
	libmceliece-20241009/crypto_kem/6688128f/vec/gf.h
	libmceliece-20241009/crypto_kem/6688128f/vec/gf_params.h
	libmceliece-20241009/crypto_kem/6688128f/vec/vec.h
	libmceliece-20241009/crypto_kem/6688128f/vec/benes.h
	libmceliece-20241009/crypto_kem/6688128f/vec/bm.h
	libmceliece-20241009/crypto_kem/6688128f/vec/controlbits.h
	libmceliece-20241009/crypto_kem/6688128f/vec/decrypt.h
	libmceliece-20241009/crypto_kem/6688128f/vec/encrypt.h
	libmceliece-20241009/crypto_kem/6688128f/vec/fft_consts.h
	libmceliece-20241009/crypto_kem/6688128f/vec/fft.h
	libmceliece-20241009/crypto_kem/6688128f/vec/fft_powers.h
	libmceliece-20241009/crypto_kem/6688128f/vec/fft_scalars_2x.h
	libmceliece-20241009/crypto_kem/6688128f/vec/fft_scalars_4x.h
	libmceliece-20241009/crypto_kem/6688128f/vec/fft_tr.h
	libmceliece-20241009/crypto_kem/6688128f/vec/hash.h
	libmceliece-20241009/crypto_kem/6688128/avx/gf_2m_mul.c
	libmceliece-20241009/crypto_kem/6688128/avx/gf_2m_mul2.c
	libmceliece-20241009/crypto_kem/6688128/avx/gf_2mt_mul.c
	libmceliece-20241009/crypto_sort/int16/portable4/sort.c
	libmceliece-20241009/crypto_sort/int32/portable4/sort.c
	libmceliece-20241009/crypto_sort/int64/portable4/sort.c
	libmceliece-20241009/crypto_kem/6688128f/vec/operations.h
	libmceliece-20241009/crypto_kem/6688128f/vec/pk_gen.h
	libmceliece-20241009/crypto_kem/6688128f/vec/sk_gen.h
	libmceliece-20241009/crypto_kem/6688128f/vec/transpose.h
	libmceliece-20241009/crypto_kem/6688128f/vec/util.h
	libmceliece-20241009/crypto_xof/shake256/unrollround/shake256.c
	libmceliece-20241009/crypto_xof/shake256/unrollround/keccak.inc
	libmceliece-20241009/crypto_kem/6688128f/vec/benes.c
	libmceliece-20241009/crypto_kem/6688128f/vec/bm.c
	libmceliece-20241009/crypto_kem/6688128f/vec/controlbits.c
	libmceliece-20241009/crypto_kem/6688128f/vec/decrypt.c
	libmceliece-20241009/crypto_xof/bitwrite16/ref/write.c
	libmceliece-20241009/crypto_kem/6688128f/vec/encrypt.c
	libmceliece-20241009/crypto_kem/6688128f/vec/shared-fft_consts.c
	libmceliece-20241009/crypto_kem/6688128f/vec/shared-fft_powers.c
	libmceliece-20241009/crypto_kem/6688128f/vec/shared-fft_scalars_2x.c
	libmceliece-20241009/crypto_kem/6688128f/vec/shared-fft_scalars_4x.c
	libmceliece-20241009/crypto_kem/6688128f/vec/fft.c
	libmceliece-20241009/crypto_kem/6688128f/vec/fft_tr.c
	libmceliece-20241009/crypto_kem/6688128f/vec/gf.c
	libmceliece-20241009/crypto_kem/6688128f/vec/kem_dec.c
	libmceliece-20241009/crypto_kem/6688128f/vec/kem_enc.c
	libmceliece-20241009/crypto_kem/6688128f/vec/kem_keypair.c
	libmceliece-20241009/crypto_kem/6688128f/vec/pk_gen.c
	libmceliece-20241009/crypto_kem/6688128f/vec/sk_gen.c
	libmceliece-20241009/crypto_kem/6688128f/vec/vec.c
	libmceliece-20241009/crypto_kem/6688128f/vec/wrap_dec.c
	libmceliece-20241009/crypto_kem/6688128f/vec/wrap_enc.c
	libmceliece-20241009/crypto_kem/6688128f/vec/wrap_keypair.c"
###

set -e
cd $1
echo -n '/*  $'
echo 'OpenBSD: $ */'
echo
echo '/*'
sed -e 's/^/ * /' < $LICENSE
echo ' *'
sed -e 's/^/ * /' < $PEOPLE
echo ' *'
echo ' * This file is generated by mceliece6688128f.sh from these files:'
echo ' *'
echo "$FILES" | sed -e 's/\t/ * /'
echo ' *'
echo ' */'
echo
echo '#include "includes.h"'
echo
echo '#if USE_MCELIECE6688128X25519 && !USE_LIBMCELIECE'
echo
echo '#include <string.h>'
echo '#include "crypto_api.h"'
echo
# Map the types used in this code to the ones in crypto_api.h.  We use #define
# instead of typedef since some systems have existing intXX types and do not
# permit multiple typedefs even if they do not conflict.
for t in int8 uint8 int16 uint16 int32 uint32 int64 uint64; do
	echo "#define $t crypto_${t}"
done

echo "typedef int8_t crypto_uint8_signed;"
echo "typedef int16_t crypto_uint16_signed;"
echo "typedef int32_t crypto_uint32_signed;"
echo "typedef int64_t crypto_uint64_signed;"
echo

for x in 8 16 32 64 ; do
	echo "extern volatile crypto_int${x} mceliece_int${x}_optblocker;"
	echo "extern volatile crypto_uint${x} mceliece_uint${x}_optblocker;"
	echo "extern volatile crypto_uint${x}_signed mceliece_uint${x}_signed_optblocker;"
done

echo
for i in $FILES; do
	echo "/* from $i */"
	# Changes to all files:
	#  - remove all includes, we inline everything required.
	#  - make functions not required elsewhere static.
	#  - rename the functions we do use.
	#  - remove unnecessary defines and externs.
	sed -e "/#include/d" \
	    -e "s/crypto_kem_/crypto_kem_mceliece6688128f_/g" \
	    -e "s/^static void crypto_kem_/void crypto_kem_/g" \
	    -e "s/^int16 /static int16 /g" \
	    -e "s/^uint16 /static uint16 /g" \
	    -e "/^extern /d" \
	    -e "/perm_check/d" \
	    -e '/CRYPTO_NAMESPACE/d' \
	    -e '/CRYPTO_SHARED_NAMESPACE/d' \
	    -e 's/if defined(__GNUC__) && defined(__/if !MCELIECE_NO_ASM \&\& defined(__GNUC__) \&\& defined(__/' \
	    -e 's/[	 ]*$//' \
	    $i | \
	case "$i" in
	*/cryptoint/crypto_int8.h)
	    sed -e "s/static void crypto_int8_/void crypto_int8_/"
	    ;;
	*/cryptoint/crypto_int16.h)
	    sed -e "s/static void crypto_int16_/void crypto_int16_/"
	    ;;
	*/cryptoint/crypto_int32.h)
	# Use int64_t for intermediate values in crypto_int32_minmax to
	# prevent signed 32-bit integer overflow when called by
	# crypto_sort_int32. Original code depends on -fwrapv (we set -ftrapv)
	    sed -e "s/crypto_int32 crypto_int32_r = crypto_int32_y ^ crypto_int32_x;/crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;/" \
		-e "s/crypto_int32 crypto_int32_z = crypto_int32_y - crypto_int32_x;/crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;/"
	    ;;
	*/cryptoint/crypto_uint8.h)
	    sed -e "s/static void crypto_uint8_/void crypto_uint8_/"
	    ;;
	*/cryptoint/crypto_uint16.h)
	    sed -e "s/static void crypto_uint16_/void crypto_uint16_/"
	    ;;
	*/cryptoint/crypto_uint32.h)
	    sed -e "s/static void crypto_uint32_/void crypto_uint32_/"
	    ;;
	*/cryptoint/crypto_int64.h)
	    sed -e "s/static void crypto_int64_store/void crypto_int64_store/" \
	        -e "s/static void crypto_int64_minmax/void crypto_int64_minmax/"
	    ;;
	*/cryptoint/crypto_uint64.h)
	    sed -e "s/static void crypto_uint64_/void crypto_uint64_/" \
	        -e "s/static void crypto_int64_minmax/void crypto_int64_minmax/"
	    ;;
	*/int16/portable4/sort.c)
	    sed -e "s/void crypto_sort[(]/void crypto_sort_int16(/g"
	    ;;
	*/int32/portable4/sort.c)
	    sed -e "s/void crypto_sort[(]/void crypto_sort_int32(/g"
	    ;;
	*/int32/portable5/sort.c)
	    sed -e "s/crypto_sort_smallindices/crypto_sort_int32_smallindices/"\
	        -e "s/void crypto_sort[(]/void crypto_sort_int32(/g"
	    ;;
	*/uint32/useint32/sort.c)
	    sed -e "s/void crypto_sort/void crypto_sort_uint32/g"
	    ;;
	*/int64/portable4/sort.c)
	    sed -e "s/void crypto_sort/void crypto_sort_int64/g"
	    ;;
	# Silence false-alarm gcc warning about unitialized variable.
	*/kem_keypair.c)
	    sed -e "s/uint64_t pivots;/uint64_t pivots = 0;/"
	    ;;
	# This file clobbers namespace for one-letter variable names.
	*/controlbits.c)
	    cat
	    echo '#undef A'
	    echo '#undef B'
	    echo '#undef q'
	    ;;
	# Fix namespace.
	*/crypto_xof/bitwrite16/ref/write.c)
	    sed -e "s/crypto_xof(/crypto_xof_bitwrite16(/"
	    ;;
	# Uses variable B0 which is used for termios B0 control flag.
	*/crypto_xof/shake256/unrollround/shake256.c)
	    echo 'static void keccak(uint64_t *s);'
	    echo '#undef B0 /* /usr/include/asm-generic/termbits.h */'
	    sed -e "s/crypto_xof(/crypto_xof_shake256(/"
	    ;;
	# Poor-man's #include now that we removed all #include's above.
	*/shared-fft_*.c)
	    INC=$(echo $i | sed -e "s,/shared-fft_,/," -e "s,.c$,.data,")
	    DATA=$(echo $(cat $INC))
	    sed -e "s/};/$DATA\n};/"
	    ;;
	# Default: pass through.
	*)
	    cat
	    #sed -e "s/^void /static void /g" \
	#	-e "s/^int /static int /g"
	    ;;
	esac
done
echo '#endif /* USE_MCELIECE6688128X25519 && !USE_LIBMCELIECE */'
