#!/bin/sh
#       $OpenBSD: $
#       Placed in the Public Domain.
#
AUTHOR="supercop-20241022/crypto_sign/sphincs256/ref/implementors"
FILES="supercop-20241022/crypto_sign/sphincss256sha256robust/ref/params.h
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/utils.h
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/address.h
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/thash.h
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/sha256.h
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/sha256.c
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/thash_sha256_robust.c
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/utils.c
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/address.c
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/hash.h
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/hash_sha256.c
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/wots.h
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/wots.c
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/apiorig.h
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/fors.h
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/fors.c
       supercop-20241022/crypto_sign/sphincss256sha256robust/ref/sign.c"
###

set -e
cd $1
echo -n '/*  $'
echo 'OpenBSD: $ */'
echo
echo '/*'
echo ' * CC0-1.0, Authors:'
sed -e 's/^/ * - /' < $AUTHOR
echo ' */'
echo
echo '#include <string.h>'
echo
echo '#include "crypto_api.h"'
echo
# Map the types used in this code to the ones in crypto_api.h.  We use #define
# instead of typedef since some systems have existing intXX types and do not
# permit multiple typedefs even if they do not conflict.
for t in int8 uint8 int16 uint16 int32 uint32 int64 uint64; do
	echo "#define $t crypto_${t}"
done

echo
for i in $FILES; do
	echo "/* from $i */"
	# Changes to all files:
	#  - expand CRYPTO_NAMESPACE() namespacing define
	#  - remove all includes, we inline everything required.
	#  - make functions not required elsewhere static.
	#  - rename the functions we do use.
	sed \
	    -e "/#include/d" \
	    -e "s/^void /static void /g" \
	    -e 's/CRYPTO_NAMESPACE[(]\([a-zA-Z0-9_]*\)[)]/crypto_sign_sphincsplus_ref_\1/g' \
	    $i | \
	case "$i" in
	*/crypto_sign/sphincss256sha256robust/ref/sign.c)
	    # rename signing function to the name OpenSSH expects
	    sed -e "s/crypto_sign/crypto_sign_sphincsplus/g"
	    ;;
	# Default: pass through.
	*)
	    cat
	    ;;
	esac
	echo
done
