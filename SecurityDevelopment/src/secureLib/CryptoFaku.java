package secureLib;

import java.nio.charset.Charset;

public class CryptoFaku {


	//za RC4 algoritam
	public static void swap(int a[], int i, int j)
	{
	int temp;
	temp=a[i];
	a[i]=a[j];
	a[j]=temp;
	}
	
	/**
	 * 
	 */
	public static void rc4Sifrovanje(){
		int j;
		int i;
		//duzina u bajtovima
		int duzinaVektoraStanja=6;
		int S[] = new int[duzinaVektoraStanja];
		
		//kljuc binary
		//http://www.branah.com/ascii-converter
		//S I F R O V A N O
		//0x53 0x49 0x46 0x52 0x4f 0x56 0x41 0x4e 0x4f
		//83 73 70 82 79 86 65 78 79
		//1010011 1001001 1000110 1010010 1001111 1010110 1000001 1001110 1001111
//		int kljuc[] = {83, 73, 70, 82, 79, 86, 65, 78, 79};
		
		//2F AC 30 CC F9
		//47 172 48 204 249
		int kljuc[] = {47, 172, 48, 204, 249};
		
		int brojac=1;

		int plaintText[] = {83, 73, 71, 85, 82, 78, 79, 83, 84, 83, 73,83, 84, 69, 77, 65};
		// za dekriptovanje
//		int plaintText[] = {84, 77, 64, 85, 84, 75, 75, 86, 87, 82, 78, 86, 86, 64, 73, 67};

		int cypherText[] = new int[plaintText.length];
		//KSA
		System.out.println("KSA");
		for(i =0; i<duzinaVektoraStanja; i++)
			S[i]=i;
		System.out.print("S = [ ");
		for(int k=0;k<duzinaVektoraStanja;k++)
			System.out.print(S[k]+" ");
		System.out.println("]");
		System.out.print("kljuc = [");
		for(int l=0;l<kljuc.length;l++)
			System.out.print(" "+kljuc[l]);
		System.out.println(" ]");
		System.out.println();

		j=0;
		for(i = 0; i<duzinaVektoraStanja; i++){
			int temporary = (j+S[i]+kljuc[i % kljuc.length]);
			j= temporary % duzinaVektoraStanja;
			
			System.out.println(brojac+++". KSA iteracija");
			System.out.print("S = [ ");
			for(int k=0;k<duzinaVektoraStanja;k++)
				System.out.print(S[k]+" ");
			System.out.println("]");
			System.out.print("kljuc = [");
			for(int l=0;l<kljuc.length;l++)
				System.out.print(" "+kljuc[l]);
			System.out.println(" ]");
			System.out.println("i = "+i);
			System.out.println("j = ("+j+"+"+S[i]+"+"+kljuc[i%kljuc.length] +") mod "+duzinaVektoraStanja+" = "+j);
			
			swap(S,i,j);
			System.out.print("swap(S["+i+"],S["+j+"]) => S=[ ");
			for(int k=0;k<duzinaVektoraStanja;k++)
				System.out.print(S[k]+" ");
			System.out.println("]");
			System.out.println();
			
		}

		
		//PRGA
		System.out.println("PRGA");
		System.out.print("S = [ ");
		for(int k=0;k<duzinaVektoraStanja;k++)
			System.out.print(S[k]+" ");
		System.out.println("]");
		
		i=0;
		j=0;
		brojac = 1;
		
		int k;
		for (int l=0;l<plaintText.length;l++){
			System.out.println(brojac+++". PRGA iteracija");
			System.out.print("S = [ ");
			for(int n=0;n<duzinaVektoraStanja;n++)
				System.out.print(S[n]+" ");
			System.out.println("]");
			i=(i+1)% duzinaVektoraStanja;
			j=(j+S[i])% duzinaVektoraStanja;
			
			swap(S,i,j);

			System.out.println("i = ("+i+"+1) mod "+duzinaVektoraStanja+" = "+i);
			System.out.println("j = ("+j+"+"+S[i]+") mod "+duzinaVektoraStanja+" = "+j);
			System.out.print("swap(S["+i+"],S["+j+"]) => S=[ ");
			for(int n=0;n<duzinaVektoraStanja;n++)
			System.out.print(S[n]+" ");
			System.out.println("]");
			k=S[(S[i]+S[j])% duzinaVektoraStanja];
			System.out.println("k = S[("+S[i]+"+"+S[j]+") mod "+duzinaVektoraStanja+"] = "+k );
			cypherText[l]=((byte)k^ (byte)plaintText[l]);
			System.out.println("cipher = "+Integer.toBinaryString(k)+" XOR "
					+Integer.toBinaryString(plaintText[l])+" = "
					+Integer.toBinaryString(cypherText[l])+" = "
					+cypherText[l]);
			System.out.println();
		}
		System.out.print("Ciphertext: [ " );
		for (int m=0;m<cypherText.length;m++)
		System.out.print(cypherText[m]+" ");
		System.out.println("]");

	}
	
	

	
	public static void monoalphabeticSubstitution(){
		//ulazni alphabet tekst
		String text = "zaue zikarza pa2ija i3ciza bopajopa o jokok 3a 3ua ro jheke ui32ici wal oee3zo3ci le 3pok4 ui3eo: zi o ha2iniki, zi o i4wepi, zi o 3uhci. 3pa aco ka r4wojo, iln2are ze rz4 ceuzo i zapa3a2o;i zi 4 karez 3a eozoh za reka r4no n2areci wal phcon2epixa i 4se3e. jo2ijo piaa heluiaieca o sipoc4 3pa 3a piaa ocpehek4 fanopa le3ara i eojel4k4 fanope wa3e4de. leco ejo e4zo nopohica o za3hadeue 4 sipoc4,zekler piaa za pirica sipoc zano za3hada. bej i bopaj joki za reka sipoc4 ziace chesi or sipoce 3pa. i leb4ro, zikarez bopaj za 4ua re oruahi 3had4 jok4 iue, zano 3euo 3had4 jok4 zaue. zek3hadziki ka bopaj joki 4ua re 3a 4r4wi ozo2ijo 4 3pok4 3had4, jeo aco 3a rh4ni 4r4wa 4 3pok4 za3had4. i re za eha3eepe xa24 zod ui32adi ze 3pok4 3had4, jeo aco wi 4herio re u4 3a ronori2e za3hade. 3pa 34 pa2ija 3hada 324bekza, i zaue bopaje joki ka ilui32io karz4 3had4. za chawe ehikecaie xazici eo ehepri zano eo 3hx4.bopaje zeki3jhazika po2iuo jere ne po2iuo lekarzo 3e fanopiu zaro3cexiue, bej jere ne po2iuo wea lwon fanopiv zaro3ceceje.zea zaehikecai, co koa zika zea zeoee3ziki ehocipzij, kah ba3co or zaehikecaie zeehepiuo roxzika rowhon ehikecaie. e2i 2eszi ehikecai, co ka zeknohi i zeoee3ziki bopaj 4 zeaok ojo2izi.zaehikecai ze3 n2are ba3co 3euo jhol kerz4 lew24r4 joka 3a roxzika uosa re orhajza, i re ka 3a zekler i 3eu 3ciri; e2i ze3 2eszi ehikecai n2are jhol 3pok4 ehihor4 joke ka eoec4zo 34ehocze zeaok ehihori, i jhol 3poka izcaha3a joki 34 3ephaazo zaehoukaziipi 3e zeaiu rowhou i zeaiu uihou.zekwoii ehikecaii, co 34 ozi 4 bikau rh4acp4 uosauo re d4ciuo, e re 3a ieej o3adeuo rowho jeo re zek3hrebzika helnopeheuo. 3e zaehikecaiau 3a uosa helnopeheci, e2i 3a za uosa d4ceci. cejo ka d4cefa karze uahe ehikecai3cpe. i4wep ka o3adefa joka ka hal42cec 3piv rh4niv o3adefe, lwih 3piv rh4niv uon4dzo3ci bopajopiv, zekpiaiv i zekbi3cikiv. i4wep ka zekpadi ilpoh 3zena le i24lik4, i zekr4wii rojel uodi le ejxik4. ejo i4wep lepi3i or zeaa 32oworza poia, leaco za eha3cez4 po2aci ozi joki wi vca2i re eha3cez4... 4 i4wepi 3a o3ade piaa zano aco chawe, eeci piaa zano aco 3a ui32i, 3efe piaa zano aco 3a sipi i jesa ozo aco zi 3eui za pah4kauo. nopohici o i4wepi, co ka pad eoue2o po2aci. bopaj o sazi lze 3euo ozo aco ka 3eu ilui32io i 4 aco ka 3euo oz pahopeo. ori3ce, 4 orzo3iue iluam4 bopaje i saza, saze ka 4paj 34eahiohzike. uosre wi 4se3i i4wepi wi2i uefi jere wi3uo uon2i po2aci 3euo oza joka wi3uo vca2i. pa2ija lpalra 3a pira 3euo 4 34coz4 reze, e pa2ija i4wepi 3euo 4 34coz4 3hada.";
		String[] rijec = text.split(" ");
		String[][] nizovirijeci= new String[20][];
		for (int i=0;i<nizovirijeci.length;i++)
			nizovirijeci[i]= new String[250];
//		LinkedList<String> listaRijeci = new LinkedList<String>();
//		System.out.println("Broj rijeci u tekstu: "+rijec.length);//437
		for(int i=0;i<rijec.length;i++){
//			System.out.println(rijec[i]);
			for(int j=0;j<25;j++){
				if (rijec[i].length()==j){
					for(int k=0;k<nizovirijeci[j].length;k++){
//						if(nizovirijeci[j][k]!=null && nizovirijeci[j][k]==rijec[i])
//							break;
						if(nizovirijeci[j][k]==null){
							nizovirijeci[j][k]=rijec[i];
							break;
						}
					}
				}
			}
		}


		for(int i=0;i<nizovirijeci.length;i++)
			for(int j=0;j<nizovirijeci[i].length;j++)
				if(nizovirijeci[i][j]!=null)
//					System.out.println("["+i+"],["+j+"]="+nizovirijeci[i][j]);
					System.out.println(nizovirijeci[i][j]);


/* ne valja		
		String digram[]=new String[1000];
		int brojac=0;
		for(int i=0;i<nizovirijeci[2].length;i++)
			for(int j=0;j<nizovirijeci[2].length;j++)
					if(nizovirijeci[2][j]!=null && digram[i]!=null
							&& digram[i].equals(nizovirijeci[2][j]))
						digram[brojac++]=nizovirijeci[2][j];
					else
						continue;
		
		for(int i=0;i<digram.length;i++)
			if(digram[i]!=null)
				System.out.println("["+i+"]="+digram[i]);
*/
	}
	
	
	
	/**
	 * PC2 DES table.
	 * 
	 * @param cd
	 * @return
	 */
	public static String PC2(String cd){
		char[] cdChar = cd.toCharArray();
		char[] kChar = new char[48];

		kChar[00] = cdChar[13];
		kChar[01] = cdChar[16];
		kChar[02] = cdChar[10];
		kChar[03] = cdChar[23];
		kChar[04] = cdChar[00];
		kChar[05] = cdChar[04];
		kChar[06] = cdChar[02];
		kChar[07] = cdChar[27];
		kChar[8] = cdChar[14];
		kChar[9] = cdChar[05];
		kChar[10] = cdChar[20];
		kChar[11] = cdChar[9];
		kChar[12] = cdChar[22];
		kChar[13] = cdChar[18];
		kChar[14] = cdChar[11];
		kChar[15] = cdChar[03];
		kChar[16] = cdChar[25];
		kChar[17] = cdChar[07];
		kChar[18] = cdChar[15];
		kChar[19] = cdChar[06];
		kChar[20] = cdChar[26];
		kChar[21] = cdChar[19];
		kChar[22] = cdChar[12];
		kChar[23] = cdChar[01];
		kChar[24] = cdChar[40];
		kChar[25] = cdChar[51];
		kChar[26] = cdChar[30];
		kChar[27] = cdChar[36];
		kChar[28] = cdChar[46];
		kChar[29] = cdChar[54];
		kChar[30] = cdChar[29];
		kChar[31] = cdChar[39];
		kChar[32] = cdChar[50];
		kChar[33] = cdChar[44];
		kChar[34] = cdChar[32];
		kChar[35] = cdChar[47];
		kChar[36] = cdChar[43];
		kChar[37] = cdChar[48];
		kChar[38] = cdChar[38];
		kChar[39] = cdChar[55];
		kChar[40] = cdChar[33];
		kChar[41] = cdChar[52];
		kChar[42] = cdChar[45];
		kChar[43] = cdChar[41];
		kChar[44] = cdChar[49];
		kChar[45] = cdChar[35];
		kChar[46] = cdChar[28];
		kChar[47] = cdChar[31];

		return new String(kChar);
	}
	
	/**
	 * PC1 DES table.
	 * 
	 * @param initKey
	 * @return
	 */
	public static String PC1(String initKey){
		char[] initKeyChar = initKey.toCharArray();
		char[] c0d0Char = new char[56];
		
		c0d0Char[0] = initKeyChar[56];
		c0d0Char[1] = initKeyChar[48];
		c0d0Char[2] = initKeyChar[40];
		c0d0Char[3] = initKeyChar[32];
		c0d0Char[4] = initKeyChar[24];
		c0d0Char[5] = initKeyChar[16];
		c0d0Char[6] = initKeyChar[8];
		
		c0d0Char[7] = initKeyChar[0];
		c0d0Char[8] = initKeyChar[57];
		c0d0Char[9] = initKeyChar[49];
		c0d0Char[10] = initKeyChar[41];
		c0d0Char[11] = initKeyChar[33];
		c0d0Char[12] = initKeyChar[25];
		c0d0Char[13] = initKeyChar[17];
		
		c0d0Char[14] = initKeyChar[9];
		c0d0Char[15] = initKeyChar[1];
		c0d0Char[16] = initKeyChar[58];
		c0d0Char[17] = initKeyChar[50];
		c0d0Char[18] = initKeyChar[42];
		c0d0Char[19] = initKeyChar[34];
		c0d0Char[20] = initKeyChar[26];
		
		c0d0Char[21] = initKeyChar[18];
		c0d0Char[22] = initKeyChar[10];
		c0d0Char[23] = initKeyChar[2];
		c0d0Char[24] = initKeyChar[59];
		c0d0Char[25] = initKeyChar[51];
		c0d0Char[26] = initKeyChar[43];
		c0d0Char[27] = initKeyChar[35];
		
		c0d0Char[28] = initKeyChar[62];
		c0d0Char[29] = initKeyChar[54];
		c0d0Char[30] = initKeyChar[46];
		c0d0Char[31] = initKeyChar[38];
		c0d0Char[32] = initKeyChar[30];
		c0d0Char[33] = initKeyChar[22];
		c0d0Char[34] = initKeyChar[14];
		
		c0d0Char[35] = initKeyChar[6];
		c0d0Char[36] = initKeyChar[61];
		c0d0Char[37] = initKeyChar[53];
		c0d0Char[38] = initKeyChar[45];
		c0d0Char[39] = initKeyChar[37];
		c0d0Char[40] = initKeyChar[29];
		c0d0Char[41] = initKeyChar[21];
		
		c0d0Char[42] = initKeyChar[13];
		c0d0Char[43] = initKeyChar[5];
		c0d0Char[44] = initKeyChar[60];
		c0d0Char[45] = initKeyChar[52];
		c0d0Char[46] = initKeyChar[44];
		c0d0Char[47] = initKeyChar[36];
		c0d0Char[48] = initKeyChar[28];
		
		c0d0Char[49] = initKeyChar[20];
		c0d0Char[50] = initKeyChar[12];
		c0d0Char[51] = initKeyChar[4];
		c0d0Char[52] = initKeyChar[27];
		c0d0Char[53] = initKeyChar[19];
		c0d0Char[54] = initKeyChar[11];
		c0d0Char[55] = initKeyChar[3];					
												
		return new String(c0d0Char);
	}
		
	
	/**
	 * Generates Key for each DES iteration.
	 * 
	 * @param allCXDX
	 */
	public static void generateKforEachIteration(String[] cxdx){
		String[] kx = new String[17];
		for (int i=1;i<kx.length;i++){
			System.out.print("K"+i+": ");
			kx[i]=PC2(cxdx[i]);
			System.out.format("%s%n", kx[i]);
		}
	}
	
	public static String[] generateCXDX(String initKey){
		String[] cxdx = new String[17];
		
		cxdx[0] = PC1(initKey);
		cxdx[1] = shiftLeftBy(1, cxdx[0].substring(0,28))+shiftLeftBy(1, cxdx[0].substring(28));
		cxdx[2] = shiftLeftBy(1, cxdx[1].substring(0,28))+shiftLeftBy(1, cxdx[1].substring(28));
		cxdx[3] = shiftLeftBy(2, cxdx[2].substring(0,28))+shiftLeftBy(2, cxdx[2].substring(28));
		cxdx[4] = shiftLeftBy(2, cxdx[3].substring(0,28))+shiftLeftBy(2, cxdx[3].substring(28));
		cxdx[5] = shiftLeftBy(2, cxdx[4].substring(0,28))+shiftLeftBy(2, cxdx[4].substring(28));
		cxdx[6] = shiftLeftBy(2, cxdx[5].substring(0,28))+shiftLeftBy(2, cxdx[5].substring(28));
		cxdx[7] = shiftLeftBy(2, cxdx[6].substring(0,28))+shiftLeftBy(2, cxdx[6].substring(28));
		cxdx[8] = shiftLeftBy(2, cxdx[7].substring(0,28))+shiftLeftBy(2, cxdx[7].substring(28));
		cxdx[9] = shiftLeftBy(1, cxdx[8].substring(0,28))+shiftLeftBy(1, cxdx[8].substring(28));
		cxdx[10] = shiftLeftBy(2, cxdx[9].substring(0,28))+shiftLeftBy(2, cxdx[9].substring(28));
		cxdx[11] = shiftLeftBy(2, cxdx[10].substring(0,28))+shiftLeftBy(2, cxdx[10].substring(28));
		cxdx[12] = shiftLeftBy(2, cxdx[11].substring(0,28))+shiftLeftBy(2, cxdx[11].substring(28));
		cxdx[13] = shiftLeftBy(2, cxdx[12].substring(0,28))+shiftLeftBy(2, cxdx[12].substring(28));
		cxdx[14] = shiftLeftBy(2, cxdx[13].substring(0,28))+shiftLeftBy(2, cxdx[13].substring(28));
		cxdx[15] = shiftLeftBy(2, cxdx[14].substring(0,28))+shiftLeftBy(2, cxdx[14].substring(28));
		cxdx[16] = shiftLeftBy(1, cxdx[15].substring(0,28))+shiftLeftBy(1, cxdx[15].substring(28));
		
		return cxdx;
	}
	
	/**
	 * Shifts circularly input string characters for <i>places</i> places to the left.
	 * DES
	 * 
	 * @param places
	 * @param input
	 * @return
	 */
	public static String shiftLeftBy(int places, String input){
		String shiftedLeft = "";
		if(places<=input.length()){
			String leftPart = input.substring(0,places);
			String rightPart = input.substring(places);
			shiftedLeft = rightPart+leftPart;
		}
		return shiftedLeft;
	}
	

	
	/**
	 * Calculates DES keys throughout all iterations. If needed, right padding is added. Default padding is 0.
	 * 
	 * @param initKeyString
	 * @param paddingString padding to be added on the right
	 */
	public void desKeyIterations(String initKeyString, String...paddingString){
		
		String pad = "0";
		
		if(paddingString.length > 0)
			pad = paddingString[0];
		
		
		//String initKey = "01001011"+"01001100"+"01001010"+"01010101"+"01000011"+"01001011"+"01001100"+"01001010";														     
		System.out.println("Init key string:\n" + initKeyString);
		
		
		
		String initKeyBinary = textToBinary(initKeyString);
		System.out.println("Init key binary:\n" + initKeyBinary);
		System.out.println("Init key length:\n" + initKeyBinary.length());
		//test from script: String initKey = "0001001100110100010101110111100110011011101111001101111111110001";
		
		if(initKeyBinary.length() < 64){
			initKeyBinary = String.format("%-64s", initKeyBinary).replace(" ", pad);
			System.out.println("Init key right padded with " + pad + ":\n" + initKeyBinary);
		}
		else if (initKeyBinary.length() > 64) {
			initKeyBinary = initKeyBinary.substring(0,64);
			System.out.println("Init key string cuted:\n" + initKeyBinary);
		}
		
		System.out.println();
		
		String[] cxdx = generateCXDX(initKeyBinary);
		
		for(int i=0;i<cxdx.length;i++)
			System.out.format("c%sd%s: %s%n",i,i, cxdx[i]);

		generateKforEachIteration(cxdx);
	}
	
	
	/**
	 * Converts UTF-8 string to binary string
	 * 
	 * @param s
	 * @return
	 */
	public String textToBinary(String s){
		byte[] bytes = s.getBytes(Charset.forName("UTF-8"));
		StringBuffer sb = new StringBuffer();
		for (byte b : bytes) {
			sb.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(" ", "0"));
		}
		
		return sb.toString();
	}
	
	/**
	 * Converts Binary string to UTF-8 string
	 * 
	 * @param s
	 * @return
	 */
	public String binaryToText(String s){
		StringBuilder sb = new StringBuilder();
		for (String s1 : s.split("(?<=\\G.{8})")) 
			sb.append((char)Integer.parseInt(s1, 2));
		
		return sb.toString();
	}
	
	
	/**
	 * @param args
	 */
		public static void main(String[] args) {
		//rc4Sifrovanje();
		//aes();
		//System.out.println("H: "+(int)'H');
		
		CryptoFaku cf = new CryptoFaku();
		//String s1 = cf.binaryToText("0100101101001100010010100101010101000011010010110100110001001010");
		//String s = "KLJUCKLJ";
		String s = "LOZINKA";
		cf.desKeyIterations(s);
	}
	
	public static int aesSubBytesCell(int cell){
		
		int[][] sBox = {
			{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, 
			{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, 
			{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, 
			{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, 
			{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, 
			{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, 
			{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, 
			{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
			{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, 
			{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, 
			{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, 
			{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, 
			{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, 
			{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, 
			{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
			{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
		};
		
		return sBox[cell/0x10][cell%0x10];
	}
	
	/**
	 * 
	 * @param 
	 * @return
	 */
	public static int[] aesRCon(int round){
		int[] vector = new int[4];
		switch (round) {
		case 1:
			vector[0] = 0x01;
			break;
		case 2:
			vector[0] = 0x02;
			break;
		case 3:
			vector[0] = 0x04;
			break;
		case 4:
			vector[0] = 0x08;
			break;
		case 5:
			vector[0] = 0x10;
			break;
		case 6:
			vector[0] = 0x20;
			break;
		case 7:
			vector[0] = 0x40;
			break;
		case 8:
			vector[0] = 0x80;
			break;
		case 9:
			vector[0] = 0x1b;
			break;
		case 10:
			vector[0] = 0x36;
			break;

		default:
			break;
		}
		
		vector[1]= 0x00;
		vector[2]= 0x00;
		vector[3]= 0x00;
		
		
		return vector;
	}
	
	
	/**
	 * Generates keys for n rounds.
	 * n=1 for first round, n=2 for second etc.
	 * 
	 * @param n
	 * @param key
	 */
	public static void aesKeySchedulingByRound(int n, int[][][] k){
		
		System.out.format("key%s: %n", 0);
		printBlock4x4AsBlock(k[0]);
		
		for(int i=1;i<=n;i++){
			
			//RotWord
			k[i][0][0]= k[i-1][1][3];
			k[i][1][0]= k[i-1][2][3];
			k[i][2][0]= k[i-1][3][3];
			k[i][3][0]= k[i-1][0][3];
			
			//SubBytes
			for(int m=0;m<k[i].length;m++)
				k[i][m][0] = aesSubBytesCell(k[i][m][0]);
			
			//xor 0 column
			int[] rCon = aesRCon(i);
			for(int m=0;m<k[i].length;m++)
				k[i][m][0] ^= k[i-1][m][0] ^ rCon[m];

			//xor 1 column
			for(int m=0;m<k[i].length;m++)
				k[i][m][1] = k[i][m][0] ^ k[i-1][m][1];
			
			//xor 2 column
			for(int m=0;m<k[i].length;m++)
//				k[i][m][2] = k[i][m][0] ^ k[i-1][m][2];
				k[i][m][2] = k[i][m][1] ^ k[i-1][m][2];
			//xor 3 column
			for(int m=0;m<k[i].length;m++)
//				k[i][m][3] = k[i][m][0] ^ k[i-1][m][3];
				k[i][m][3] = k[i][m][2] ^ k[i-1][m][3];
			
			System.out.format("key%s: %n", i);
			printBlock4x4AsBlock(k[i]);
		}
			
	}
	
	public static void aesKeyScheduling(int rounds, int[] initKey, int[][][] key){
		
		key[0] = aesPopulateBlock4x4(initKey);
		
		aesKeySchedulingByRound(rounds, key);
		
		

	}
	
	public static int[][] aesPopulateBlock4x4(int[] input){
		int[][] output = new int[4][4];
		for(int j=0,l=0;j<output.length;j++)
			for(int k=0;k<output[0].length;k++,l++)
				output[k][j] = input[l];
		
		return output;
	}
	
	public static int[][] aesAddRoundKey(int[][] text, int[][] key){
		int[][] out4x4 = new int[4][4];
		
		for(int i=0;i<out4x4.length;i++)
			for(int j=0;j<out4x4[0].length;j++)
				out4x4[i][j] = text[i][j]^key[i][j];
		
		return out4x4;
	}
	
	public static void aes(){
		//initKey SIGURNOSTSISTEMA, reda se po kolonama zato ide key[i][k][j]
		//int [] initKey = {83, 73, 71, 85, 82, 78, 79, 83, 84, 83, 73, 83, 84, 69, 77, 65};
		int [] initKey = {0x53,0x49,0x47,0x55,0x52,0x4e,0x4f,0x53,0x54,0x53,0x49,0x53,0x54,0x45,0x4d,0x41};
		
		//internet
		//int [] initKey = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
		
		//2012 zadatak tacan, netacna ognjenova skripta
		//int[] initKey = {0x41, 0x45, 0x53, 0x4b, 0x4c, 0x4a, 0x55, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		int rounds = 10;
		int[][][] key = new int[11][4][4];
		aesKeyScheduling(rounds, initKey, key);
		
//		print3DArrayByColumnsInHexFormat("key",rounds, key);
		//test
//		int[] plainText = {0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08};
		
		//SESNAESTBAJTOVA2
		//int[] plainText = {83, 69, 83, 78, 65, 69, 83, 84, 66, 65, 74, 84, 79, 86, 65, 50}; 
		int[] plainText = {0x53,0x45,0x53,0x4e,0x41,0x45,0x53,0x54,0x42,0x41,0x4a,0x54,0x4f,0x56,0x41,0x32};
		//cipher	tacan 0x55, 0xfc, 0x11, 0xd8, 0x68, 0xcb, 0xc6, 0xa0, 0x9b, 0x83, 0x80, 0x69, 0xf0, 0x3a, 0x2, 0x86	
		
		//internet
		//int[] plainText = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
		//cypher tacan 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x4, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
		
		//2012 zadatak 3 tacan, netacna ognjenova skripta
		//int[] plainText = {0x41, 0x45, 0x53, 0x31, 0x32, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		
		int i = 0;
		int[][][] cipher = new int[11][4][4];
		cipher[i++] = aesPopulateBlock4x4(plainText);
		
		cipher[i] = aesAddRoundKey(cipher[0], key[0]);
		for(i=1;i<=rounds-1;i++){
			System.out.format("%s: %n", i);
			printBlock4x4AsBlock(cipher[i]);
			
			aesSubBytes(cipher[i]);
			aesShiftRows(cipher[i]);
			aesMixColumns(cipher[i]);
			cipher[i+1]=aesAddRoundKey(cipher[i], key[i]);
			
		}
		System.out.format("%s: %n", i);
		printBlock4x4AsBlock(cipher[i]);
		
		aesSubBytes(cipher[i]);
		aesShiftRows(cipher[i]);
		
		int[][] output = aesAddRoundKey(cipher[i], key[i]);
		
		System.out.format("output: %n");

		printBlock4x4AsBlock(output);
		printBlock4x4AsRow(output);
	}
	
	public static void print3DArrayByColumnsInHexFormat(String name, int rounds, int[][][] arrayToPrint){
		for(int i=0;i<=rounds;i++)
			for(int j=0;j<arrayToPrint[0].length;j++)
				for(int k=0;k<arrayToPrint[0][0].length;k++)
					System.out.format("%s[%s][%s][%s] = %h%n", name, i,k,j,arrayToPrint[i][k][j]);
		System.out.println();
	}
	
	public static void aesSubBytes(int[][] cipher){
		for(int i=0;i<cipher.length;i++)
			for(int j=0;j<cipher[0].length;j++)
				cipher[i][j] = aesSubBytesCell(cipher[i][j]);
	}
	
	
	public static void aesShiftRows(int[][] cipher){
		int[][] temp = new int[cipher.length][cipher[0].length];
		
		//copy because clone() didn't work
		for(int i=0;i<cipher.length;i++)
			for (int j = 0; j < cipher[0].length; j++)
				temp[i][j]=cipher[i][j];
		
		cipher[1][0]=temp[1][1];
		cipher[1][1]=temp[1][2];
		cipher[1][2]=temp[1][3];
		cipher[1][3]=temp[1][0];

		cipher[2][0]=temp[2][2];
		cipher[2][1]=temp[2][3];
		cipher[2][2]=temp[2][0];
		cipher[2][3]=temp[2][1];
		
		cipher[3][0]=temp[3][3];
		cipher[3][1]=temp[3][0];
		cipher[3][2]=temp[3][1];
		cipher[3][3]=temp[3][2];

	}
	
	public static void aesMixColumns(int[][] cipher){
		// 2 3 1 1	cipher[0][0]
		// 1 2 3 1  cipher[1][0]
		// 1 1 2 3	cipher[2][0]
		// 3 1 1 2	cipher[3][0]
		
		int[][] temp = new int[cipher.length][cipher[0].length];
		for(int i=0;i<cipher.length;i++)
			for(int j=0;j<cipher[0].length;j++)
				temp[i][j]=cipher[i][j];
		
		
		for(int i=0;i<cipher.length;i++){
			cipher[0][i]= (0x02*temp[0][i]^ifLeadingOne(temp[0][i]) ^ 0x02*temp[1][i]^ifLeadingOne(temp[1][i])^temp[1][i] ^ temp[2][i] ^ temp[3][i])%0x100;
			cipher[1][i]= (temp[0][i] ^ 0x02*temp[1][i]^ifLeadingOne(temp[1][i]) ^ 0x02*temp[2][i]^ifLeadingOne(temp[2][i])^temp[2][i] ^ temp[3][i])%0x100;
			cipher[2][i]= (temp[0][i] ^ temp[1][i] ^ 0x02*temp[2][i]^ifLeadingOne(temp[2][i]) ^ 0x02*temp[3][i]^ifLeadingOne(temp[3][i])^temp[3][i])%0x100;
			cipher[3][i]= (0x02*temp[0][i]^ifLeadingOne(temp[0][i])^temp[0][i] ^ temp[1][i] ^ temp[2][i] ^ 0x02*temp[3][i]^ifLeadingOne(temp[3][i]))%0x100;
		}
	}
	
	public static int ifLeadingOne(int num){
		if(num  >= 0x80 && num <= 0xff)
			return 0x1b;
		else 
			return 0x00;
	}
	
	public static void printBlock4x4AsRow(int[][] block){
		for(int i = 0;i<block.length;i++)
			for(int j=0;j<block[0].length;j++)
				System.out.format("0x%h, ", block[j][i]);
		System.out.println();
	}
	
	public static void printBlock4x4AsBlock(int[][] block){
		for(int i = 0;i<block.length;i++)
				System.out.format("0x%h 0x%h 0x%h 0x%h%n", block[i][0],  block[i][1],  block[i][2],  block[i][3]);
		System.out.println();
	}
}
