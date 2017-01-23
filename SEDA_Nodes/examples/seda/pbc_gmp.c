/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         A very simple Contiki application showing how Contiki programs look
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "contiki.h"
#include <stdio.h> /* For printf() */
#include "pbc_gmp_app.h"

void _kill()
{
	printf("!!!!!!!!!!!!!_kill \n");
}
void _getpid()
{
	printf("!!!!!!!!!!!!!_getpid \n");
}

#if 0
void gmp_test()
{

//GMP API test.
	static mpz_t x,y,result;
//	test_test2();
//	test_test3(x);
//	test_test4(x,x);
//	test_test(x, "76", 10);
	mpz_init_set_str(x, "76", 10);
	mpz_init_set_str(y, "92", 10);
	dump("x",x);
	dump("y",y);
	mpz_init_set_str(x, "0970af295dd96f0dd7ef2825e1e38bf1208bfe7ef41241dcc04929496cf78407296545487eb18cd0b9a1", 16); //nom
	mpz_init_set_str(y, "1fc0ac88119481a00b54d358e3e3bbe5cbb29b17780b2d53109843e71de1d58682a84977604efd80cb2a", 16); //den
	dump("x",x);
	dump("y",y);
	mpz_init(result);
	mpz_mul(result, x, y);
	dump("result",result);
//	gmp_printf("    %Zd\n"
//	"*\n"
//	"    %Zd\n"
//	"--------------------\n"
//	"%Zd\n", x, y, result);

	/* free used memory */
	printf("Hello, world4\n");
	mpz_clear(x);
	mpz_clear(y);
	mpz_clear(result);
}
	
void dump (const char *label, const mpz_t x)
{
  char *buf = mpz_get_str (NULL, 16, x);
  printf( "%s: %s\n", label, buf);
  free (buf);
}
#endif

/*---------------------------------------------------------------------------*/
PROCESS(pbc_gmp_test_process, "pbc_gmp_test_process");
AUTOSTART_PROCESSES(&pbc_gmp_test_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(pbc_gmp_test_process, ev, data)
{
	PROCESS_BEGIN();

	printf("Hello, PBC and GMP\n");

	pbc_extract_ciphertext();

	printf("Good bye, PBC and GMP\n");
	PROCESS_END();
}
/*---------------------------------------------------------------------------*/
