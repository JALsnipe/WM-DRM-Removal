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
 *  Foobar is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* General purpose elliptic curve routines. */

#include <stdio.h>
#include <stdlib.h>
#include "ecc.h"


static int ECC_param_ok(BIGNUM * p, BIGNUM * a, BIGNUM * b)
{
	BIGNUM *tmp1, *tmp2;
	BN_CTX *ctx;
	int retval;

	if ((p == NULL) || (a == NULL) || (b == NULL))
		return 0;

	tmp1 = BN_new();
	tmp2 = BN_new();
	ctx = BN_CTX_new();

	BN_mod_mul(tmp1, a, a, p, ctx);
	BN_mod_mul(tmp1, tmp1, a, p, ctx);
	BN_lshift(tmp1, tmp1, 2);
	BN_mod(tmp1, tmp1, p, ctx);

	tmp2 = BN_new();
	BN_set_word(tmp2, 27);
	BN_mod_mul(tmp2, tmp2, b, p, ctx);
	BN_mod_mul(tmp2, tmp2, b, p, ctx);

	BN_add(tmp2, tmp1, tmp2);
	BN_mod(tmp2, tmp2, p, ctx);

	retval = !BN_is_zero(tmp2);

	BN_CTX_free(ctx);
	BN_free(tmp1);
	BN_free(tmp2);

	return retval;
}


ECC *ECC_new_set(BIGNUM * p, BIGNUM * a, BIGNUM * b, ECCpt g)
{
	ECC *ecc;

	if (!ECC_param_ok(p, a, b))
		return NULL;

	ecc = malloc(sizeof(ECC));
	if (ecc != NULL) {
		ecc->modulus = BN_dup(p);
		ecc->a = BN_dup(a);
		ecc->b = BN_dup(b);
		ecc->generator.x = BN_dup(g.x);
		ecc->generator.y = BN_dup(g.y);
		ecc->pubkey.x = ecc->pubkey.y = NULL;
		ecc->privkey = NULL;
	}

	return ecc;
}


void ECC_free(ECC * ecc)
{
	if (ecc != NULL) {
		BN_free(ecc->modulus);
		ecc->modulus = NULL;
		BN_free(ecc->a);
		ecc->a = NULL;
		BN_free(ecc->b);
		ecc->b = NULL;
		BN_free(ecc->generator.x);
		ecc->generator.x = NULL;
		BN_free(ecc->generator.y);
		ecc->generator.y = NULL;
		if (ecc->pubkey.x != NULL) {
			BN_free(ecc->pubkey.x);
			ecc->pubkey.x = NULL;
			BN_free(ecc->pubkey.y);
			ecc->pubkey.y = NULL;
		}
		if (ecc->privkey != NULL) {
			BN_free(ecc->privkey);
			ecc->privkey = NULL;
		}
		free(ecc);
	}
}


void ECCpt_init(ECCpt * pt)
{
	pt->x = BN_new();
	pt->y = BN_new();
}


void ECCpt_free(ECCpt * pt)
{
	BN_free(pt->x);
	pt->x = NULL;
	BN_free(pt->y);
	pt->y = NULL;
}


int ECCpt_is_valid_pt(ECCpt * a, ECC * ecc)
{
	/*  check that y^2 = x^3 + a x + b  */
	BIGNUM *tmp1, *tmp2;
	BN_CTX *ctx;
	int retval;

	ctx = BN_CTX_new();
	tmp1 = BN_dup(a->x);
	BN_mod_mul(tmp1, tmp1, tmp1, ecc->modulus, ctx);
	BN_add(tmp1, tmp1, ecc->a);
	BN_mod_mul(tmp1, tmp1, a->x, ecc->modulus, ctx);
	BN_add(tmp1, tmp1, ecc->b);
	if (BN_cmp(tmp1, ecc->modulus) >= 0)
		BN_sub(tmp1, tmp1, ecc->modulus);

	tmp2 = BN_dup(a->y);
	BN_mod_mul(tmp2, tmp2, tmp2, ecc->modulus, ctx);

	retval = (BN_cmp(tmp1, tmp2) == 0);
	BN_free(tmp1);
	BN_free(tmp2);
	BN_CTX_free(ctx);
	return retval;
}


int ECCpt_is_equal(ECCpt * a, ECCpt * b)
{
	if (a->x->neg && b->x->neg)
		return 1;
	return ((BN_cmp(a->x, b->x) == 0) && (BN_cmp(a->y, b->y) == 0));
}


void ECCpt_add(ECCpt * r, ECCpt * a, ECCpt * b, ECC * ecc)
{
	BN_CTX *ctx;
	BIGNUM *tmp1, *tmp2;
	BIGNUM *lambda;

	if (a->x->neg) {
		BN_copy(r->x, b->x);
		BN_copy(r->y, b->y);
		return;
	}

	if (b->x->neg) {
		BN_copy(r->x, a->x);
		BN_copy(r->y, a->y);
		return;
	}

	tmp1 = BN_new();
	if (BN_cmp(a->x, b->x) == 0) {
		BN_add(tmp1, a->y, b->y);
		if (BN_cmp(tmp1, ecc->modulus) == 0) {
			BN_free(tmp1);
			r->x->neg = 1;	/*  Set to identity  */
			return;
		}
	}

	ctx = BN_CTX_new();
	tmp2 = BN_new();
	lambda = BN_new();
	if (ECCpt_is_equal(a, b)) {
		BN_set_word(tmp1, 3);
		BN_mod_mul(tmp1, tmp1, a->x, ecc->modulus, ctx);
		BN_mod_mul(tmp1, tmp1, a->x, ecc->modulus, ctx);
		BN_add(tmp1, tmp1, ecc->a);
		BN_mod(tmp1, tmp1, ecc->modulus, ctx);
		BN_lshift1(tmp2, a->y);
		BN_mod_inverse(tmp2, tmp2, ecc->modulus, ctx);
		BN_mod_mul(lambda, tmp1, tmp2, ecc->modulus, ctx);
	} else {
		BN_sub(tmp1, b->x, a->x);
		if (tmp1->neg)
			BN_add(tmp1, ecc->modulus, tmp1);
		tmp2 = BN_mod_inverse(NULL, tmp1, ecc->modulus, ctx);
		BN_sub(tmp1, b->y, a->y);
		if (tmp1->neg)
			BN_add(tmp1, ecc->modulus, tmp1);
		BN_mod_mul(lambda, tmp1, tmp2, ecc->modulus, ctx);
	}

	BN_mod_mul(tmp1, lambda, lambda, ecc->modulus, ctx);
	BN_sub(tmp1, tmp1, a->x);
	if (tmp1->neg)
		BN_add(tmp1, ecc->modulus, tmp1);
	BN_sub(tmp2, tmp1, b->x);
	if (tmp2->neg)
		BN_add(tmp2, ecc->modulus, tmp2);

	BN_sub(tmp1, a->x, tmp2);
	if (tmp1->neg)
		BN_add(tmp1, ecc->modulus, tmp1);
	BN_mod_mul(tmp1, lambda, tmp1, ecc->modulus, ctx);
	BN_sub(r->y, tmp1, a->y);
	if (r->y->neg)
		BN_add(r->y, ecc->modulus, r->y);

	BN_free(r->x);
	r->x = tmp2;
	tmp2 = NULL;

	BN_free(lambda);
	BN_free(tmp1);
	BN_CTX_free(ctx);
}


void ECCpt_mul(ECCpt * r, ECCpt * a, BIGNUM * n, ECC * ecc)
{
	ECCpt tmp;
	int numbits, i;

	tmp.x = BN_dup(a->x);
	tmp.y = BN_dup(a->y);
	r->x->neg = 1;
	numbits = BN_num_bits(n);
	for (i = numbits - 1; i >= 0; i--) {
		if (BN_is_bit_set(n, i))
			ECCpt_add(r, r, &tmp, ecc);
		if (i > 0)
			ECCpt_add(r, r, r, ecc);
	}
}
