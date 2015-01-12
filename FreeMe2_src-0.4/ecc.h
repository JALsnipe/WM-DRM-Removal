/*
 *  (C) Copyright 2001-2007 "Beale Screamer"
 *                           Michal Majchrowicz
 *
 *  This file is part of FreeMe2.
 *
 *  FreeMe2 is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  any later version.
 *
 *  FreeMe2 is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#if !defined( _ECC_H )
#define _ECC_H

#include <openssl/bn.h>

/*
 * If the "neg" field of the BIGNUM struct is set, then this point is
 * the identity.  This is a terrible way to do this, since it's not
 * clear what the future of this flag is -- however, for now it works,
 * and it's fast...
 */

typedef struct eccpt_st {
	BIGNUM *x, *y;
} ECCpt;

typedef struct eccparam_st {
	BIGNUM *modulus;	/* Curve is over Z_modulus */
	BIGNUM *a, *b;		/* Curve coefficients */
	ECCpt generator;	/* Generator for our operations */
	ECCpt pubkey;		/* Public key */
	BIGNUM *privkey;	/* Corresponding private key */
} ECC;


ECC *ECC_new_set(BIGNUM * p, BIGNUM * a, BIGNUM * b, ECCpt g);
void ECC_free(ECC * ecc);
void ECCpt_init(ECCpt * pt);
void ECCpt_free(ECCpt * pt);
int ECCpt_is_valid_pt(ECCpt * a, ECC * ecc);
int ECCpt_is_equal(ECCpt * a, ECCpt * b);
void ECCpt_add(ECCpt * r, ECCpt * a, ECCpt * b, ECC * ecc);
void ECCpt_mul(ECCpt * r, ECCpt * a, BIGNUM * n, ECC * ecc);

#endif
