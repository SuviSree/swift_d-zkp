#include<iostream>
#include<stdio.h>
#include<stdlib.h>
#include<algorithm>

using namespace std;

uint64_t p = 2147483647;

uint64_t field_add(uint64_t a, uint64_t b){
	return (a + b) % p;
}

uint64_t field_mult(uint64_t a, uint64_t b){
	return (a * b) % p;
}

void field_random_poly(uint64_t *poly, uint64_t d){
	poly = (uint64_t*) malloc ((d+1) * sizeof(uint64_t));
	for(int i = 0; i <= d; ++i)
		poly[i] = (uint64_t)((uint64_t)rand() % p); //change to OpenSLL
}

void field_poly_add(uint64_t *a, uint64_t d1, uint64_t *b, uint64_t d2, uint64_t *c){
	uint64_t d = max(d1, d2);
	
	c = (uint64_t*) malloc ((d+1) * sizeof(uint64_t));
	for(int i = 0; i<= d; ++i){
		if((i <= d1)){
			if(i <= d2)
				c[i] = field_add(a[i], b[i]);
			else{
				while(i <= d){
					c[i] = a[i];
					++i;
				}
			}	
		}
		else{
			while(i <= d){
				c[i] = b[i];
				++i;
			}
		}
	}
}

void field_print_poly(uint64_t *poly, uint64_t d){
	for(int i = 0; i <= d; ++i)
		cout<<poly[i]<<" ";
	cout<<endl;
}

int main(){
	uint64_t *x;
	uint64_t *y;
	field_random_poly(x, 3);
	field_random_poly(y, 3);
	
	
	
	field_print_poly(y, 3);
	field_print_poly(x, 3);	
}

