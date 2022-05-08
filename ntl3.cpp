//Round2 in 1 function.

#include <vector>
#include <type_traits>
#include <iostream>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h> //z_2^k[x]
#include <NTL/ZZ_pE.h> // z_2^k[x] / f[x]
#include <NTL/ZZ_pEX.h>
#include <NTL/GF2.h>  //F_2
#include <NTL/GF2X.h>
#include <NTL/vec_GF2.h>


//---------------global values-------------------------

#define d 4
#define k 64
#define M 5
#define L 1
#define N M+1
int m = M*L;

using namespace std;
using namespace NTL;



ZZ_pE inverseE(ZZ_pE p, GF2X f, int deg1, int deg2){

        ZZ_pX g;
        conv(g,p);
        GF2X f2;
        conv(f2, f);


            GF2X g2;

        ZZ_pX g1;

        for(int i= 0; i< deg1; i++)
        {
                long c1;
                conv(c1, coeff(g,i));
                SetCoeff(g2, i, (c1%((long)2)));
                long tmp= c1- (c1%((long)2));
                SetCoeff(g1, i, tmp);
        }


          GF2X gcd;
        GF2X a; //a
        GF2X b; //b
        XGCD(gcd, a, b, f2, g2);


        ZZ_pX b_p, a_p, f2_p, g2_p, h_p;

        for(int i = 0; i < deg1; ++i){
                long c1;
                    conv(c1, coeff(b,i));
                    SetCoeff(b_p, i, (c1%((long)2)));
        }

        for(int i = 0; i < deg1; ++i){
                long c1;
                    conv(c1, coeff(a,i));
                    SetCoeff(a_p, i, (c1%((long)2)));
        }

        for(int i = 0; i < deg1; ++i){
                long c1;
                    conv(c1, coeff(f2,i));
                    SetCoeff(f2_p, i, (c1%((long)2)));
        }

        for(int i = 0; i < deg1; ++i){
                long c1;
                    conv(c1, coeff(g2,i));
                    SetCoeff(g2_p, i, (c1%((long)2)));
        }

        h_p = a_p*f2_p + b_p*g2_p - 1;


        ZZ_pE b_E;
        conv(b_E, b_p);


        ZZ_pE g1_p;
        conv(g1_p, g1);



        ZZ_pE h;
        conv(h, h_p);
        h = h + (b_E * g1_p);


        ZZ_pE B_x;
        B_x=0;
        for(int i =0; i< deg2; i++)
        {
                ZZ_pE tm1=-h;
                ZZ_pE tm2=power(tm1,i);
                B_x+= tm2;
        }
        B_x = B_x * b_E;


        return(B_x);

}

void getCfactor(ZZ_pE Mat[N][N], ZZ_pE t[N][N], int p, int q, int n) {
   int i = 0, j = 0;
   for (int r= 0; r< n; r++) {
      for (int c = 0; c< n; c++)
      {
         if (r != p && c != q) {
                 t[i][j++] = Mat[r][c];
            if (j == n - 1) {
               j = 0;
               i++;
            }
         }
      }
   }
}

ZZ_pE DET(ZZ_pE Mat[N][N], int n)
{
   ZZ_pE D ;
   if (n == 1)
      return Mat[0][0];
   ZZ_pE t[N][N], s;
   ZZ_pX s_X;
   SetCoeff(s_X, 0, 1);
   conv(s, s_X);
   for (int f = 0; f < n; f++) {
      getCfactor(Mat, t, 0, f, n);
      D += s * Mat[0][f] * DET(t, n - 1);
      s = -s;
   }
   return D;
}

void ADJ(ZZ_pE Mat[N][N],ZZ_pE adj[N][N])
{
   if (N == 1) {
      adj[0][0] = 1; return;
   }
   ZZ_pE s, t[N][N];
   ZZ_pX s1;

   for (int i=0; i<N; i++) {
      for (int j=0; j<N; j++) {
         getCfactor(Mat, t, i, j, N);
         if ((i+j)%2==0)
                 SetCoeff(s1, 0, 1);
         else
                 SetCoeff(s1, 0, -1);
         conv(s,s1);

         adj[j][i] = (s)*(DET(t, N-1));
      }
   }
}

int INV(ZZ_pE Mat[N][N], ZZ_pE inv[N][N], GF2X f)
{

   ZZ_pE det = DET(Mat, N);
   std::cout<< "det\t" << det <<std::endl;

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
   }

   ZZ_pE adj[N][N];
   ADJ(Mat, adj);


   ZZ_pE dInv = inverseE(det, f, d, k);
   std::cout<< "dInv = " << dInv <<std::endl;
   std::cout<< "dInv * d = " << dInv * det <<std::endl;

   for (int i=0; i<N; i++) {
                   for (int j=0; j<N; j++){

                           inv[i][j] = adj[i][j]*dInv;
                   }
   }

        return(1);
}



void interpolation(ZZ_pE evaluations[N], GF2X f, ZZ_pE coefficients[N]){

        int i, j, l, temp;

        ZZ_pE A[N][N]; //A= Van mat
        for(i = 0; i < N; ++i){ //Binary equivalent of the evaluation points
                temp = i;
                ZZ_pX eval_pt_X;
                SetCoeff(eval_pt_X, 0, 0);



                j = 0;
                while(temp != 0){ //converting temp to binary equivalent
                        SetCoeff(eval_pt_X, j, temp%2); //
                        temp = temp / 2;
                        ++j;
                } //eval_pt_X is the polynomial having the binary equivalent of the evaluation points

                ZZ_pE eval_pt;
                conv(eval_pt, eval_pt_X); //storing the bonary equivalent of the coefficients

                for(j = 0; j < N; ++j)
                        A[i][j] = power(eval_pt, j); //populating the VAN mat
        }

        for(i = 0; i < N; ++i){
                for(j = 0; j < N; ++j)
                        std::cout<<A[i][j]<<" ";
                std::cout<<"\n";
        }
        std::cout<<"\n\n";

        ZZ_pE invA[N][N];
        INV(A, invA, f);


        std::cout<<"\n";
        for(i = 0; i < N; ++i){
                for(j = 0; j < N; ++j)
                        std::cout<<invA[i][j]<<" ";
                std::cout<<"\n";
        }

        ZZ_pX zero;
        SetCoeff(zero, 0, 0);

        ZZ_pE prod[N][N];
        for(i = 0; i < N; ++i){
                for(j = 0; j < N; ++j){
                        conv(prod[i][j], zero); //initialisiing the polynomial to zero
                        for(l = 0; l < N; ++l)
                                prod[i][j] += invA[i][l] * A[l][j];
                }
        }

        std::cout<<"\n";
        for(i = 0; i < N; ++i){
                for(j = 0; j < N; ++j)
                        std::cout<<prod[i][j]<<" ";
                std::cout<<"\n";
        }

        for(i = 0; i < N; ++i){
                conv(coefficients[i], zero);
                for(j = 0;  j < N; ++j)
                        coefficients[i] += invA[i][j] * evaluations[j];
        }
}


void Round1(ZZ_pE share[], GF2X f, ZZ_pE theta[], ZZ_pE pi[6*L + 2*M + 1], ZZ_pE pi2[6*L + 2*M + 1], ZZ_pE pi3[6*L + 2*M + 1]){

      int i, j, l, k1;

      ZZ_pX zero;
      SetCoeff(zero, 0, 0);



      ZZ_pE w[6*L];
      for(i = 0; i < 6*L; ++i)
        random(w[i]);

      std::cout<<"Reached Here"<<std::endl;

      ZZ_pEX fp[6*L]; //each poly has M+1 coefficients. And, how many such polynomials are there 6*L.
      for(j = 0; j < 6*L; ++j){
        ZZ_pE c[M+1]; //Evaluation Vectors //Evaluated dPolynomials
        c[0] = w[j]; // i_th poly will have i_th w as const
          for(l = 1; l < M ; ++l){ //rest of them are the shares
            std::cout<<l<<std::endl;
            c[l] = share[6*L*(l - 1) + j];
          }

          ZZ_pE y[M+1]; //Coefficient Matrix
          std::cout<<"Reached Here 1"<<std::endl;
          interpolation(c, f, y);

        std::cout<<"Reached Here 3"<<std::endl;
        for(l = 0; l < M+1; ++l)
          SetCoeff(fp[j], l, y[l]); //at lth degree put y[l] bcz y is the coefficient vector for the polynomial

        std::cout<<"fp["<<j<<"]"<< fp[j]<<std::endl;
      }

      ZZ_pEX P;
      SetCoeff(P, 0, 0);

      for(i = 0; i < L; ++i){
        P += theta[i] * (fp[6*i + 0]*fp[6*i + 2] + fp[6*i + 0]*fp[6*i + 3] + fp[6*i + 1]*fp[6*i + 3] + fp[6*i + 4] - fp[6*i + 5]);
      } // p is the small g circuit


      for(i = 0; i < 6*L; ++i)
        pi[i] = w[i];

      for(i = 0; i < 2*M + 1; ++i)
        pi[6*L + i] = coeff(P, i);

      //pi is the share of the party Pi


      for(i = 0; i < 6*L + 2*M + 1; ++i){
        random(pi2[i]);
        pi3[i] = pi[i] - pi2[i];
      }

      for (int i=0; i<(6*L+2*M +1); i++)
          std::cout<<"the share of pi "<<pi[i] << std::endl;

}//END OF ROUND 1
void Round2(ZZ_pE share[], ZZ_pE DIZK_share[], GF2X f, ZZ_pE fp_r[6*L], ZZ_pE& P_r_t, ZZ_pE& b_t )
{
  ZZ_pX zero;
  SetCoeff(zero, 0, 0);

  ZZ_pE Beta[M]; //M number of Beta-s
	for(int i =0; i < M; ++i){
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
  ZZ_pE w[6*L];
  for(int j = 0; j < 6*L; ++j)
    w[j]=share[j];


  //get the rest from the shares as the shares of the coefficient of the polynomial p
  ZZ_pE a_coeff[(2*M)+1];
  std::cout<<6*L<<"\t"<<m<<"\n"<<std::endl;

	int k1=0;
  for(int j = 0; j < (2*M+1); ++j){
    a_coeff[k1]=share[j];
    std::cout<<"a["<<k1<<"]="<<a_coeff[k1]<<std::endl;
		k1++;
  }

  //each element in the ring is a polynomial.
  //On top of that, the fi is a polynomial over polynomials
  //with the desired values and the evaluated points, interpolate to get the 6L polynomials.
  ZZ_pEX fp[6*L]; //each poly has M+1 coefficients. And, how many such polynomials are there 6*L. //this is the f_i. //this is polynomial of polynomials.
  //this is ZZ_PEX -- it represents polynomials over polynomials
  for(int j = 0; j < 6*L; ++j){
      		ZZ_pE c[M+1]; //Evaluation Vectors //Evaluated dPolynomials
      		c[0] = w[j]; // i_th poly will have i_th w as const
          for(int l = 1; l < M ; ++l){ //rest of them are the shares
      			std::cout<<l<<std::endl;
      			c[l] = share[6*L*(l - 1) + j];
      		}

      		ZZ_pE y[M+1];
      		interpolation(c,f,y);

      		std::cout<<"Reached Here 3"<<std::endl;
      		for(int l = 0; l < M+1; ++l)
      			SetCoeff(fp[j], l, y[l]); //at lth degree put y[l] bcz y is the coefficient vector for the polynomial

      		std::cout<<"P["<<j<<"]"<< fp[j]<<std::endl;
  	} //end of making polynomials

  //verify at the random r point on the field
  //---verify at random r point

  //ZZ_pE eval_at_r = eval(fp[0], r);


    for(int i=0; i<(6*L); i++){
      std::cout<<"reached here" <<std::endl;
        fp_r[i] = eval(fp[i], r);
        std::cout<<" fi polynomials evaluated at random r" <<fp_r[i]<<std::endl;
    }

  //------------using the shares of the coeffficient of polynomial p  --- a coefiicients
  int j=0; //j should run till 6*L
  //share of p_r

  conv(P_r_t, zero); //initialise the polynomial to 0 polynomial

  for(int i=0; i<(2*M);  i++ ){
      P_r_t+=a_coeff[i]*power(r,j);
  }
  std::cout<<" polynomial evaluated at random point r "<<P_r_t<<std::endl;

  //calculate the Beta round 2 step 3

  for(int j=0; j<(6*L); j++){

        ZZ_pE sum;
      for(int k1=0; k1< (2*M); k1++){
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
void Round3( ZZ_pE fp_r[], ZZ_pE p_r_t, ZZ_pE b_t, ZZ_pE fp_r_prime[], ZZ_pE p_r_t_prime, ZZ_pE b_t_prime, ZZ_pE theta[] ){
  std::cout<<"\n --------------------ROUND 3--------- \n "<<std::endl;
  std::cout<<"received shares from Round 2"<<std::endl;
  for(int i=0; i<(6*L); i++){
    std::cout<<" fp_r is = "<<fp_r[i];
  }

    std::cout<<" p_r_t ="<<p_r_t<<std::endl;

    std::cout<< "b_t ="<<b_t<<std::endl;

  ZZ_pE f_prime_j_r[6*L];
  for(int j=0; j<(6*L); j++){
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
  for(int i = 0; i < L; ++i){
    P_check += theta[i] * (fp_r_prime[6*i + 0]*fp_r_prime[6*i + 2] + fp_r_prime[6*i + 0]*fp_r_prime[6*i + 3] + fp_r_prime[6*i + 1]*fp_r_prime[6*i + 3] + fp_r_prime[6*i + 4] - fp_r_prime[6*i + 5]);
  } //


  if ((p_r==P_check) && (b==0)){
    std::cout<<"ACCEPT"<<std::endl;
  }
  else
    std::cout<<"ABORT"<<std::endl;
}

int main()
{

  GF2X f;

  SetCoeff(f, 3, 1);
  SetCoeff(f, 2, 1);
  SetCoeff(f, 0, 1);

  std::cout<<"polynomial f " <<f<<std::endl;


  long modulus = (long) pow(2, k); // long can store only 64 bit number. Therefore, the largest number it can store is 2^{64} - 1
  ZZ_p::init(conv<ZZ>(modulus) + 1); //adding 1 so that the p modulus is 2^{64} //
  std::cout<<"modulus="<<ZZ_p::modulus()<<std::endl;
  std::cout<<"\n\n";


  ZZ_pX fZ;
  for(int i = 0; i < d; ++i){
        long c1;
        conv(c1, coeff(f,i));
        SetCoeff(fZ, i, (c1%((long)2)));
  }

  ZZ_pE::init((const ZZ_pX) fZ);


  std::cout<<"Testing inverseE function"<<std::endl;
  std::cout<<"------------------------------------------------------------------------"<<std::endl;
  ZZ_pE temp_inverse_check, temp_inverse_check2;
  for(int i = 0; i < 10; ++i){
          random(temp_inverse_check);
          std::cout<<temp_inverse_check<<std::endl;
          temp_inverse_check2 = inverseE(temp_inverse_check, f, 4, k);
          std::cout<<temp_inverse_check2<<std::endl;
          std::cout<<temp_inverse_check2 * temp_inverse_check<<std::endl;
          std::cout<<std::endl;
  }
  std::cout<<"------------------------------------------------------------------------\n"<<std::endl;


//in our prog,, evaluations = shares got
  ZZ_pE evaluations[N], coefficients[N];
  for(int i = 0; i < N; ++i)
          random(evaluations[i]);

  //interpolation(evaluations, f, coefficients);

  ZZ_pE fE;
  conv(fE, fZ);

  ZZ_pE pi_share[6*m]; //xi
  for(int i=0; i<6*m; i++)
    random(pi_share[i]);

  for(int i=0; i<6*m; i++)
    std::cout<<pi_share[i]<<std::endl;

	ZZ_pE theta[L];
	for(int i =0; i < L; ++i)
		random(theta[i]);

	ZZ_pE pi[6*L + 2*M + 1];
	ZZ_pE pi2[6*L + 2*M + 1];
	ZZ_pE pi3[6*L + 2*M + 1];

	Round1(pi_share, f, theta, pi, pi2, pi3);

  ZZ_pE fp_r[6*L];
	ZZ_pE P_r_t;
	ZZ_pE b_t;

	ZZ_pE pi_share2[6*m]; //xi
  for(int i=0; i<6*m; i++)
    random(pi_share2[i]);



	Round2( pi_share2, pi2, f, fp_r, P_r_t, b_t);

  ZZ_pE fp_r_prime[6*L];
  ZZ_pE P_r_t_prime;
  ZZ_pE b_t_prime;

  Round2(pi_share2, pi3, f, fp_r_prime, P_r_t_prime, b_t_prime);

  std::cout<<"b_t" <<b_t<<std::endl;

  Round3(fp_r, P_r_t, b_t, fp_r_prime, P_r_t_prime, b_t_prime,theta);


  return(0);
}
