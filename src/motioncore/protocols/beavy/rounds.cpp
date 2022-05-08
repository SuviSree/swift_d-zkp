#include "beavy_provider.h"

//Round 2 section b is run by each of the two parties. So, in two_party_backend, make the two data structures needed for each party, the structures in step b.

//---------------global values-------------------------
#define N 6 // NUMSHARES
#define d 4 // DEGREE_POLY//d = number of coefficients of the polynomial. //(d-1) degree polynomial has d number of coefficients
#define k 20 // RINGSIZE// Z_2^k is the k here. Attenuate the value according to how big a Ring you want

int m = NUMgGATES * NUMcGATES;
using namespace std;
using namespace NTL;
namespace MOTION::proto::beavy {



			ZZ_pE inverseE(ZZ_pE p, GF2X f, int deg1, int deg2){ // we find the inverse of g polynomial here, passed as p polynomial, in the extended quotient ring quotiented by f poly
				//std::cout<<"p in inverseE" << p << std::endl;
				ZZ_pX g;
				conv(g,p);
				//std::cout<< "g poly " <<g<<std::endl;
				GF2X f2; // since no modulus operation over GF2X. Hence jst copying the poly f into f2.
				conv(f2, f);
				//std::cout<<"polynomial f2 " <<f2<<std::endl;

			    GF2X g2;

				ZZ_pX g1; //g_cap

			    for(int i= 0; i< deg1; i++)
			    {
			    	long c1;
			    	conv(c1, coeff(g,i));
			    	//std::cout<< " coefficients of g " <<c1<<std::endl;
			    	SetCoeff(g2, i, (c1%((long)2)));
			    	long tmp= c1- (c1%((long)2));
			    	SetCoeff(g1, i, tmp);	 //g1 = g - g2
			    }

			  	//std::cout<<"g2\t"<<g2<<std::endl;
			  	//std::cout<<"g1\t"<<g1<<std::endl;

			  	GF2X gcd;
				GF2X a; //a
				GF2X b; //b
				XGCD(gcd, a, b, f2, g2);
				//std::cout<< " a= "<< a << std::endl;
				//std::cout<< " b= "<< b << std::endl;
				//std::cout<< " d= "<< d << std::endl;

				ZZ_pX b_p, a_p, f2_p, g2_p, h_p;

				for(int i = 0; i < deg1; ++i){
					long c1;
			    	conv(c1, coeff(b,i));
			    	//std::cout<< " coefficients of b " <<c1<<std::endl;
			    	SetCoeff(b_p, i, (c1%((long)2)));
				}

				for(int i = 0; i < deg1; ++i){
					long c1;
			    	conv(c1, coeff(a,i));
			    	//std::cout<< " coefficients of b " <<c1<<std::endl;
			    	SetCoeff(a_p, i, (c1%((long)2)));
				}

				for(int i = 0; i < deg1; ++i){
					long c1;
			    	conv(c1, coeff(f2,i));
			    	//std::cout<< " coefficients of b " <<c1<<std::endl;
			    	SetCoeff(f2_p, i, (c1%((long)2)));
				}

				for(int i = 0; i < deg1; ++i){
					long c1;
			    	conv(c1, coeff(g2,i));
			    	//std::cout<< " coefficients of b " <<c1<<std::endl;
			    	SetCoeff(g2_p, i, (c1%((long)2)));
				}

				//std::cout<<"b_p\t"<<b_p<<std::endl;
				//std::cout<<"a_p\t"<<a_p<<std::endl;
				//std::cout<<"f2_p\t"<<f2_p<<std::endl;
				//std::cout<<"g2_p\t"<<g2_p<<std::endl;

				h_p = a_p*f2_p + b_p*g2_p - 1;
				//std::cout<<"h_p\t"<<h_p<<std::endl;

				ZZ_pE b_E;
				conv(b_E, b_p);
				//std::cout<<"b_E\t"<<b_E<<std::endl;

				ZZ_pE g1_p;
				conv(g1_p, g1);

				//std::cout<<"g1_p\t"<<g1_p<<std::endl;

				ZZ_pE h;
				conv(h, h_p);
				h = h + (b_E * g1_p);
				//std::cout<<"h\t"<<h<<std::endl;

				ZZ_pE B_x;
				B_x=0;
				for(int i =0; i< deg2; i++) //k=10
				{
					ZZ_pE tm1=-h;
					ZZ_pE tm2=power(tm1,i);
					B_x+= tm2;
				}
				B_x = B_x * b_E;

				//std::cout<< " B(x) = " << B_x <<std::endl;

				return(B_x);

			}
			void getCfactor(ZZ_pE Mat[N][N], ZZ_pE t[N][N], int p, int q, int n) {
			   int i = 0, j = 0;
			   for (int r= 0; r< n; r++) {
			      for (int c = 0; c< n; c++) //Copy only those elements which are not in given row r and column c:
			      {
			         if (r != p && c != q) {
			         	t[i][j++] = Mat[r][c]; //If row is filled increase r index and reset c index
			            if (j == n - 1) {
			               j = 0;
			               i++;
			            }
			         }
			      }
			   }
			}

			ZZ_pE DET(ZZ_pE Mat[N][N], int n) //to find determinant
			{
			   ZZ_pE D ;
			   if (n == 1)
			      return Mat[0][0];
			   ZZ_pE t[N][N]; //store cofactors
			   int s = 1; //store sign multiplier //
			   for (int f = 0; f < n; f++) {
			      //For Getting Cofactor of M[0][f] do
			      getCfactor(Mat, t, 0, f, n);
			      D += s * Mat[0][f] * DET(t, n - 1);
			      s = -s;
			   }
			   return D;
			}

			void ADJ(ZZ_pE Mat[N][N],ZZ_pE adj[N][N])
			//to find adjoint matrix
			{
			   if (N == 1) {
			      adj[0][0] = 1; return;
			   }
			   ZZ_pE s, t[N][N];
			   ZZ_pX s1;

			   for (int i=0; i<N; i++) {
			      for (int j=0; j<N; j++) {
			         //To get cofactor of M[i][j]
			         getCfactor(Mat, t, i, j, N);
			         if ((i+j)%2==0)
			         	SetCoeff(s1, 0, 1);
			         else
			         	SetCoeff(s1, 0, -1);//sign of adj[j][i] positive if sum of row and column indexes is even.
			         conv(s,s1);
			         //std::cout<< "s =" <<s<<std::endl;
			         adj[j][i] = (s)*(DET(t, N-1)); //Interchange rows and columns to get the transpose of the cofactor matrix
			      }
			   }
			}

			int INV(ZZ_pE Mat[N][N], ZZ_pE inv[N][N], GF2X f)
			{

			   ZZ_pE det = DET(Mat, N); //this is a valu0
			   std::cout<< "det\t" << d <<std::endl;

			   ZZ_pX d1;
			   conv(d1, det);

			   int flag = 0;
			   long d0;
			   for(int i = 0; i < d; ++i){
			   		conv(d0, coeff(d1, i));
			   		if((d0 % 2) == 1){
			   			flag = 1;
			   			break;
			   		}
			   }

			   if (flag == 0) {
			      cout << "can't find its inverse";
			      return 0;
			      //return false;
			   }

			   ZZ_pE adj[N][N];
			   ADJ(Mat, adj);


			   ZZ_pE dInv = inverseE(det, f, 4, 3);
			   std::cout<< "dInv = " << dInv <<std::endl;
			   std::cout<< "dInv * d = " << dInv * det <<std::endl;

			   for (int i=0; i<N; i++) {
			   		for (int j=0; j<N; j++){

			   			inv[i][j] = adj[i][j]*dInv;
			   		}
			   }

				return(1);
			}

void BEAVYProvider::Round3( ZZ_pE fp_r[], ZZ_pE p_r_t, ZZ_pE b_t, ZZ_pE fp_r_prime[], ZZ_pE p_r_t_prime, ZZ_pE b_t_prime, ZZ_pE theta[] ){
    std::cout<<"\n --------------------ROUND 3--------- \n "<<std::endl;
    std::cout<<"received shares from Round 2"<<std::endl;
    for(int i=0; i<(6*NUMcGATES); i++){
      std::cout<<" fp_r is = "<<fp_r[i];
    }

      std::cout<<" p_r_t ="<<p_r_t<<std::endl;

      std::cout<< "b_t ="<<b_t<<std::endl;

		ZZ_pE f_prime_j_r[6*NUMcGATES];
		for(int j=0; j<(6*NUMcGATES); j++){
			f_prime_j_r[j]=fp_r_prime[j] + fp_r[j];
    }

		ZZ_pE p_r;
		p_r=p_r_t + p_r_t_prime;

		ZZ_pE b;
		b=b_t+b_t_prime;

		//check
		ZZ_pX zero;
	  SetCoeff(zero, 0, 0);

		ZZ_pE P_check;
		conv(P_check, zero);
		for(int i = 0; i < NUMcGATES; ++i){
			P_check += theta[i] * (fp_r_prime[6*i + 0]*fp_r_prime[6*i + 2] + fp_r_prime[6*i + 0]*fp_r_prime[6*i + 3] + fp_r_prime[6*i + 1]*fp_r_prime[6*i + 3] + fp_r_prime[6*i + 4] - fp_r_prime[6*i + 5]);
		} //


		if ((p_r==P_check) && (b==0)){
			std::cout<<"ACCEPT"<<std::endl;
		}
		else
			std::cout<<"ABORT"<<std::endl;

}




void BEAVYProvider::Round2(ZZ_pE share[], ZZ_pE DIZK_share[], GF2X f, ZZ_pE fp_r[6*NUMcGATES], ZZ_pE P_r_t, ZZ_pE b_t)
{
  ZZ_pX zero;
  SetCoeff(zero, 0, 0);

  ZZ_pE Beta[NUMgGATES]; //M number of Beta-s
	for(int i =0; i < NUMgGATES; ++i){
		random(Beta[i]);
		std::cout<<"Beta["<<i<<"]="<<Beta[i]<<std::endl;
	}

	//--------------all parties will have to do the above by itself----------------------
		// for(int j=0; j<L; j++)
	// 	std::cout<<"Beta["<<j<<"]="<<Beta[j]<<std::endl;

std::cout<<" P(i-1), P(i+1) each do the below by themselves" <<std::endl;
//Round2 Function - Step b will be called by each party.

	//sample random r from the extended ring
	ZZ_pE r;
	random(r);
  std::cout<<"r="<<r<<std::endl;

	//-----------------------each party part-----------------
  //get the w from the shares
  ZZ_pE w[6*NUMcGATES];
  for(int j = 0; j < 6*NUMcGATES; ++j)
    w[j]=share[j];


  //get the rest from the shares as the shares of the coefficient of the polynomial p
  ZZ_pE a_coeff[(2*NUMgGATES)+1];
  std::cout<<6*NUMcGATES<<"\t"<<m<<"\n"<<std::endl;

	int k1=0;
  for(int j = 0; j < (2*NUMgGATES+1); ++j){
    a_coeff[k1]=share[j];
    std::cout<<"a["<<k1<<"]="<<a_coeff[k1]<<std::endl;
		k1++;
  }

  //each element in the ring is a polynomial.
  //On top of that, the fi is a polynomial over polynomials
  //with the desired values and the evaluated points, interpolate to get the 6L polynomials.
  ZZ_pEX fp[6*NUMcGATES]; //each poly has M+1 coefficients. And, how many such polynomials are there 6*L. //this is the f_i. //this is polynomial of polynomials.
  //this is ZZ_PEX -- it represents polynomials over polynomials
  for(int j = 0; j < 6*NUMcGATES; ++j){
      		ZZ_pE c[NUMgGATES+1]; //Evaluation Vectors //Evaluated dPolynomials
      		c[0] = w[j]; // i_th poly will have i_th w as const
          for(int l = 1; l < NUMgGATES ; ++l){ //rest of them are the shares
      			std::cout<<l<<std::endl;
      			c[l] = share[6*NUMcGATES*(l - 1) + j];
      		}
          //shares and the constant terms have been set //now interp[olate  //make the Vandermonde matrix
          ZZ_pE A[NUMgGATES+1][NUMgGATES+1]; //Vandermonde Matrix
    			for(int l = 0; l < NUMgGATES+1; ++l){ // these are th evaluation points
        				ZZ_pX tmp;
        				if(l == 0)
        					SetCoeff(tmp, 0, 0);
        				else
        					SetCoeff(tmp, l, 1); //
        				//we need M+1 distinct evaluation points.  Evaluation points are the polynomials zero polynomial, 1,.... ,M Polynomial
        				ZZ_pE tmp2;
        				conv(tmp2, tmp);

        				for(int k1=0; k1< NUMgGATES+1; k1++){
        					A[l][k1] = power(tmp2, k1); //V Mat
        					std::cout<<A[l][k1]<<" ";
        				}
        				std::cout<<std::endl;
          }
          std::cout<<"Reached Here 2"<<std::endl;
      		//Interpolation
      		ZZ_pE invA[NUMgGATES+1][NUMgGATES+1];
      		INV(A, invA, f);

      		ZZ_pE y[NUMgGATES+1]; //Coefficient Matrix
      		for(int l = 0; l < NUMgGATES+1; ++l){
        			conv(y[l], zero);

        			for(int k1 = 0; k1 < NUMgGATES+1; ++k1){
        				y[l] += invA[l][k1]*c[k1]; //y=A^(-1)*c
        			}
      		}
      		std::cout<<"Reached Here 3"<<std::endl;
      		for(int l = 0; l < NUMgGATES+1; ++l)
      			SetCoeff(fp[j], l, y[l]); //at lth degree put y[l] bcz y is the coefficient vector for the polynomial

      		std::cout<<"P["<<j<<"]"<< fp[j]<<std::endl;
  	} //end of making polynomials

  //verify at the random r point on the field
  //---verify at random r point

  //ZZ_pE eval_at_r = eval(fp[0], r);


    for(int i=0; i<(6*NUMcGATES); i++){
      std::cout<<"reached here" <<std::endl;
        fp_r[i] = eval(fp[i], r);
        std::cout<<" fi polynomials evaluated at random r" <<fp_r[i]<<std::endl;
    }

  //------------using the shares of the coeffficient of polynomial p  --- a coefiicients
  int j=0; //j should run till 6*L
  //share of p_r

  conv(P_r_t, zero); //initialise the polynomial to 0 polynomial

  for(int i=0; i<(2*NUMgGATES);  i++ ){
      P_r_t+=a_coeff[i]*power(r,j);
  }
  std::cout<<" polynomial evaluated at random point r "<<P_r_t<<std::endl;

  //calculate the Beta round 2 step 3

  for(int j=0; j<(6*NUMcGATES); j++){

        ZZ_pE sum;
      for(int k1=0; k1< (2*NUMgGATES); k1++){
            ZZ_pX jpol;
            SetCoeff( jpol, (long)0, (long)j);
            ZZ_pE jpol2;
            conv(jpol2, jpol);
            auto temp=a_coeff[j]*(power(jpol2,k1));
            sum+=temp;
						std::cout<<"sum ="<<sum <<std::endl;
            j++;
      }
      b_t=Beta[j]*sum; //Beta[j] is ZZ_pE. sum is ZZ_pE.
  }

  std::cout << " the b_t needed = " <<b_t <<std::endl;




//

  //Round3(share, fp_r, P_r_t, b_t, fp_r_prime, P_r_t_prime, b_t_prime); //share is the x_i things

}//end of Round 2








void BEAVYProvider::Round1(ZZ_pE share[], GF2X f, ZZ_pE theta[], ZZ_pE pi[6*NUMcGATES + 2*NUMgGATES + 1], ZZ_pE pi2[6*NUMcGATES + 2*NUMgGATES + 1], ZZ_pE pi3[6*NUMcGATES + 2*NUMgGATES + 1]){

	int i, j, l, k1;

	ZZ_pX zero;
	SetCoeff(zero, 0, 0);



	ZZ_pE w[6*NUMcGATES];
	for(i = 0; i < 6*NUMcGATES; ++i)
		random(w[i]);

	std::cout<<"Reached Here"<<std::endl;

	ZZ_pEX fp[6*NUMcGATES]; //each poly has M+1 coefficients. And, how many such polynomials are there 6*L.
	for(j = 0; j < 6*NUMcGATES; ++j){
		ZZ_pE c[NUMgGATES+1]; //Evaluation Vectors //Evaluated dPolynomials
		c[0] = w[j]; // i_th poly will have i_th w as const
		for(l = 1; l < NUMgGATES ; ++l){ //rest of them are the shares
			std::cout<<l<<std::endl;
			c[l] = share[6*NUMcGATES*(l - 1) + j];
		}
		std::cout<<"Reached Here 1"<<std::endl;
		ZZ_pE A[NUMgGATES+1][NUMgGATES+1]; //Vandermonde Matrix
		for(l = 0; l < NUMgGATES+1; ++l){ // these are th evaluation points
			ZZ_pX tmp;
			if(l == 0)
				SetCoeff(tmp, 0, 0);
			else
				SetCoeff(tmp, l, 1); //
			//we need M+1 distinct evaluation points.  Evaluation points are the polynomials zero polynomial, 1,.... ,M Polynomial
			ZZ_pE tmp2;
			conv(tmp2, tmp);

			for(k1=0; k1< NUMgGATES+1; k1++){
				A[l][k1] = power(tmp2, k1); //V Mat
				std::cout<<A[l][k1]<<" ";
			}
			std::cout<<std::endl;
		}
		std::cout<<"Reached Here 2"<<std::endl;
		//Interpolation
		ZZ_pE invA[NUMgGATES+1][NUMgGATES+1];
		INV(A, invA, f);

		ZZ_pE y[NUMgGATES+1]; //Coefficient Matrix
		for(l = 0; l < NUMgGATES+1; ++l){
			conv(y[l], zero);

			for(k1 = 0; k1 < NUMgGATES+1; ++k1){
				y[l] += invA[l][k1]*c[k1]; //y=A^(-1)*c
			}
		}
		std::cout<<"Reached Here 3"<<std::endl;
		for(l = 0; l < NUMgGATES+1; ++l)
			SetCoeff(fp[j], l, y[l]); //at lth degree put y[l] bcz y is the coefficient vector for the polynomial

		std::cout<<"P["<<j<<"]"<< fp[j]<<std::endl;
	}

	ZZ_pEX P;
	SetCoeff(P, 0, 0);

	for(i = 0; i < NUMcGATES; ++i){
		P += theta[i] * (fp[6*i + 0]*fp[6*i + 2] + fp[6*i + 0]*fp[6*i + 3] + fp[6*i + 1]*fp[6*i + 3] + fp[6*i + 4] - fp[6*i + 5]);
	} // p is the small g circuit


	for(i = 0; i < 6*NUMcGATES; ++i)
		pi[i] = w[i];

	for(i = 0; i < 2*NUMgGATES + 1; ++i)
		pi[6*NUMcGATES + i] = coeff(P, i);

	//pi is the share of the party Pi


	for(i = 0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i){
		random(pi2[i]);
		pi3[i] = pi[i] - pi2[i];
	}

	for (int i=0; i<(6*NUMcGATES+2*NUMgGATES +1); i++)
			std::cout<<"the share of pi "<<pi[i] << std::endl;




	//Pi2 is the share of the other party


}

}

//----------------here we are declaring the
//all parties together receive Beta1, Beta......, BetaM  From The extended Ring. and r from the the Extened Ring.
//here we are sampling through random function-----------------

//-------------global values-----------------------------

//------------P_i+1 and P_(i-1) do the following-------------------

//------------parse the p() share received as below----------------
//here we are sampling the share as our own.




  //Step c. Party P_(i-1) sends f1, f2, .....  to P_(i+1)
