/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rsa;

import java.lang.Math;
import java.math.BigInteger;
import java.io.*;
import java.util.*;
import java.lang.*;
import java.time.*;
import jdk.nashorn.internal.runtime.arrays.ArrayLikeIterator;

/**
 *
 * @author matheus
 */
public class RSA {
    private static String input = "";
    private static ArrayList<BigInteger> M;
    private static BigInteger P;
    private static BigInteger Q;
    private static BigInteger N;
    private static BigInteger E;
    private static BigInteger D;
    final static String MSG = "Esta é uma mensagem criptografada";
    private static ArrayList<BigInteger> msgCriptografada;
    private static String msgDescriptografada;
    final static int NUM_BITS = 16;
    final static ArrayList CHAVE_PUBLICA = new ArrayList();
    final static ArrayList CHAVE_PRIVADA = new ArrayList();
    
    private static long duracaoDescriptografia=0;
    private static long duracaoCriptografia=0;
    private static long duracaoForcaBruta=0;

    public static void main(String[] args) {
        
        long inicioCriptografia = System.currentTimeMillis();
        msgCriptografada = encriptografa();
        duracaoCriptografia += System.currentTimeMillis() - inicioCriptografia;
        
        System.out.println("\nMensagem criptografada: " + msgCriptografada);
        System.out.println("(em " + duracaoCriptografia + "ms)");
        
        long inicioDescriptografia = System.currentTimeMillis();
        msgDescriptografada = descriptografa(msgCriptografada, D, N);
        duracaoDescriptografia += System.currentTimeMillis() - inicioDescriptografia;
        
        System.out.println("\nMensagem desCriptografada: " + msgDescriptografada);
        System.out.println("(em " + duracaoDescriptografia + "ms)");
        
        
        long inicioForcaBruta = System.currentTimeMillis();
        BigInteger e = new BigInteger(Integer.toString(geraIntPrimoAleatorio(1000)));
        String msgDescriptografadaForcaBruta = ataqueForcaBruta(MSG, N);
        duracaoForcaBruta = System.currentTimeMillis() - inicioForcaBruta;

        System.out.println("\nMensagem descriptografada por força bruta: " + msgDescriptografadaForcaBruta);
        System.out.println("(em " + duracaoForcaBruta + "ms)");
        
    }
    
    public static ArrayList<BigInteger> encriptografa() {
        long inicioConversoes = System.currentTimeMillis();
        
        System.out.println("Mensagem orginial: " + MSG);
        
        ArrayList<Integer> ascii = stringParaAscii(MSG);
        
        System.out.println("\nMensagem em ASCII: " + ascii);
        
        ArrayList<String> binarios = asciiParaBinarios(ascii);

        ArrayList<String> binariosFormatados = formatarBinarios(binarios, 4);
        
        long duracaoConversoes = System.currentTimeMillis() - inicioConversoes;
        
        duracaoCriptografia += duracaoConversoes;
        
        long inicioM = System.currentTimeMillis();
        M = binariosParaBigInts(binariosFormatados);
        long duracaoM = System.currentTimeMillis() - inicioM;
        duracaoCriptografia += duracaoM;
        
        System.out.println("\nM: " + M);
        
        long inicioPQ = System.currentTimeMillis();
        P = geraBigIntPrimoAleatorio(NUM_BITS);
        Q = geraBigIntPrimoAleatorio(NUM_BITS);
        long duracaoPQ = System.currentTimeMillis() - inicioPQ;
        duracaoCriptografia += duracaoPQ;

        System.out.println("\nP: " + P);
        
        System.out.println("\nQ: " + Q);
        
        long inicioN = System.currentTimeMillis();
        N = P.multiply(Q);
        long duracaoN = System.currentTimeMillis() - inicioN;
        duracaoCriptografia += duracaoN;
        
        System.out.println("\nN: " + N);
        
        
        long inicioE = System.currentTimeMillis();
        E = new BigInteger(Integer.toString(geraIntPrimoAleatorio(1000)));
        long duracaoE = System.currentTimeMillis() - inicioE;
        
        
        long inicioD = System.currentTimeMillis();
        BigInteger aux = P.subtract(BigInteger.ONE).multiply(Q.subtract(BigInteger.ONE));
        // aux = (P-1)*(Q-1)
        D = inversoModular(E, aux);
        long duracaoD = System.currentTimeMillis() - inicioD;
        
        duracaoCriptografia += duracaoE;
        duracaoCriptografia += duracaoD;
        
        System.out.println("\nE: " + E);
        
        System.out.println("\nD: " + D);
        
        CHAVE_PUBLICA.add(E);
        CHAVE_PUBLICA.add(N);
        
        System.out.println("\nChave pública: " + CHAVE_PUBLICA);
        
        CHAVE_PRIVADA.add(D);
        CHAVE_PRIVADA.add(N);
        
        System.out.println("\nChave privada: " + CHAVE_PRIVADA);
        
        
        ArrayList<BigInteger> ret = new ArrayList<>();
        
        for (int i = 0; i < M.size(); i++) {
            ret.add(expoenteModular(M.get(i), E, N));
        }

        return ret;
    }
    
    public static String descriptografa(ArrayList<BigInteger> msgCriptografada, BigInteger d, BigInteger n) {
        ArrayList<BigInteger> aux = new ArrayList<>();

        for (int i = 0; i < msgCriptografada.size(); i++) {
            aux.add(expoenteModular(msgCriptografada.get(i), d, n));
        }
        
        ArrayList<String> binariosAgain = bigIntParaBinarios(aux, 8);
        
        ArrayList<Integer> asciiAgain = binariosParaAscii(binariosAgain);
        
        String msgAgain = asciiParaString(asciiAgain);
        
        return msgAgain;
    }
    
    public static String ataqueForcaBruta(String msg, BigInteger n) {
        BigInteger p = raizBigInt(n);
        BigInteger zero = new BigInteger("0");
        BigInteger um = new BigInteger("1");
        BigInteger dois = new BigInteger("2");
        
        if(p.mod(new BigInteger("2")).equals(zero)) {
            p = p.subtract(um);
        }

        
        System.out.println("\nraiz n: " + p);
        
        BigInteger q = p;
        
        while (!p.multiply(q).equals(n)) {
            p = p.subtract(dois);
            
            q = N.divide(p);
        }
        
        
        
        BigInteger aux = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger d = inversoModular(E, aux);
        
        String msgDescriptografadaForcaBruta = descriptografa(msgCriptografada, d, N);
        
        return msgDescriptografadaForcaBruta;
    }
    
    // converte a mensagem original para uma lista de inteiros
    // que contém o código ascii de cada caracter da mensagem
    public static ArrayList<Integer> stringParaAscii(String msg){
        ArrayList<Integer> codigosAscii = new ArrayList<>();
        
        for (int i=0; i<msg.length(); i++){
            codigosAscii.add((int) msg.charAt(i));
        }
        
        return codigosAscii;
    }
    
    // recebe uma lista de códigos ascii e converte cada ascii int
    // para binário de 8 bits
    // o último elemento, se necessário, é preenchido com zeros à esquerda
    public static ArrayList<String> asciiParaBinarios(ArrayList<Integer> ascii) {
        
        ArrayList<String> binarios = new ArrayList<>();
        
        int a;
        for (int i=0; i<ascii.size(); i++){
           a = ascii.get(i);
           StringBuilder binario = new StringBuilder();
           
           while (a > 0) {
                    int b = a % 2;
                    binario.append(b);
                    
                    a = a >> 1; // shift de bits para a direita
            }
           
           while (binario.toString().length() < 8) {
               binario.append("0");
           }
           
           binarios.add(binario.reverse().toString());

        }

        return binarios;
    }
    
    // recebe um array list com binario de 8 digitos e o numero de chars por bloco
    // retorna um array list com binarios de 8*tamBloco digitos concatenados
    // o ultimo elemento, se necessário, é preenchido com zeros à esquerda
    public static ArrayList<String> formatarBinarios (ArrayList<String> binarios, int tamBloco) {
        ArrayList<String> binariosFormatados = new ArrayList<>();
        String aux = "";

        for (int i = 0; i < binarios.size(); i++) {

            if (i % tamBloco == 0 && i != 0) {
                binariosFormatados.add(aux);
                aux = "";
            }
            
            aux = aux.concat(binarios.get(i));
            
            if (i == binarios.size() - 1) {
                
                while (aux.length() < tamBloco * 8) {
                    aux = "0".concat(aux);
                }
                
                binariosFormatados.add(aux);
                
            }
        }
        
        return binariosFormatados;
    }
    
    // recebe um array list de binários formatados em 32 bits e 
    // retorna um array list com os respectivos BigInts
    public static ArrayList<BigInteger> binariosParaBigInts(ArrayList<String> binariosFormatados) {
       
        ArrayList<BigInteger> bigInts = new ArrayList<>();
        BigInteger potencia = new BigInteger("0");;
        BigInteger acumulador = new BigInteger("0");
        BigInteger dois = new BigInteger("2");
        
        int expoente = 0;
        
        for (int i = 0; i < binariosFormatados.size(); i++) {
            for (int j = binariosFormatados.get(i).length() - 1; j >= 0; j--) {
                
                if (binariosFormatados.get(i).charAt(j) == '1') {
                    potencia = dois.pow(expoente);
                    acumulador = acumulador.add(potencia);
                }
                
                expoente++;
            }
            
            bigInts.add(acumulador);
            acumulador = BigInteger.ZERO;
            expoente = 0;
        }

        return bigInts;
    }
    
    // recebe a quantidade de bits do futuro primo aleatório
    // chama o método para gerar um bigInt aleatório 
    // passando o intervalo [2^numeroBits, 2^numeroBits-1]  
    // e chama o método de Miller-Rabin para testar se o aleatório gerado é primo
    public static BigInteger geraBigIntPrimoAleatorio(int numBits) {
        BigInteger bigIntAleatorio;
        
        BigInteger um = new BigInteger("1");
        BigInteger minimo = new BigInteger("2").pow(numBits);
        BigInteger maximo = new BigInteger("2").pow(numBits+1).subtract(um);
        
        do {
            bigIntAleatorio = bigIntAleatorio(minimo, maximo);
        } while (!testaPrimalidade(bigIntAleatorio, 20));
                
        BigInteger bigIntPrimo = bigIntAleatorio;
        
        return bigIntPrimo;
    }
    
    // recebe o intervalo
    // e retorna um bigInt aleatório dentro deste
    public static BigInteger bigIntAleatorio(BigInteger minimo, BigInteger maximo) {
        Random aux = new Random();
        BigInteger aleatorio;
        
        do {
            aleatorio = new BigInteger(maximo.bitLength(), aux);
        } while (aleatorio.compareTo(minimo) < 0 || aleatorio.compareTo(maximo) > 0);
        return aleatorio;
    }
    
    // Algoritmo de Miller-Rabin para verificar se dado número é primo
    // com dado numeroIteracoes
    public static boolean testaPrimalidade(BigInteger n, int numeroIteracoes) {
        BigInteger zero = new BigInteger("0");
        BigInteger um = new BigInteger("1");
        BigInteger dois = new BigInteger("2");
        BigInteger tres = new BigInteger("3");
        
        if (n.compareTo(tres) < 0 || n.mod(dois) == zero) {
            return false;        
        }
        
        int s = 0;
        BigInteger d = n.subtract(um);
        
        while (d.mod(dois).equals(zero)) {
            s++;
            d = d.divide(dois);
        }
        
        for (int i = 0; i < numeroIteracoes; i++) {
            BigInteger a = bigIntAleatorio(dois, n.subtract(um));
            BigInteger x = a.modPow(d, n);
            
            if (x.equals(um) || x.equals(n.subtract(um))) {
                continue;
            }
            int r = 0;
            for (r = 0; r < s; r++) {
                x = x.modPow(dois, n);
                if (x.equals(um)) {
                    return false;
                }
                if (x.equals(n.subtract(um))) {
                    break;
                }
            }
            if (r == s) {
                return false;
            }
        }        
        return true;
    }
    
    // chama o Crivo de Eratostenes passando máximo
    // e escolhe uma posição aleatória do vetor de primos retornado pelo Crivo
    public static int geraIntPrimoAleatorio (int maximo) {
        int primoAleatorio;
  
        ArrayList<Integer> primos = crivoEratostenes(maximo);

        Random aux = new Random();
        int indiceAleatorio = aux.nextInt(primos.size());

        primoAleatorio = primos.get(indiceAleatorio);

        return primoAleatorio;
    }
    
    // cria um vetor de booleanos com tamanho = maximo
    // seta true ou false conforme o índice corresponda ou não à um primo
    // e retorna um arraylist com todos os primos até o valor máximo
    public static ArrayList<Integer> crivoEratostenes(int maximo) {
        boolean []ehPrimo = new boolean[maximo+1];
        ArrayList<Integer> primos = new ArrayList<>();
        
        for (int i=0; i<=maximo; i++){
            ehPrimo[i] = true;
        }
        
        for (int i=2; i<=maximo; i++){
            if (ehPrimo[i]){
                for (int j=i; i*j<maximo; j++){
                    ehPrimo[i*j] = false;
                }
            }
        }

        for (int i = 2; i < maximo; i++) {
            if (ehPrimo[i]){
              primos.add(i);
            }
        }
        
        return primos;
    }
    
    // recebe E e  aux = (P-1)*(Q-1)
    // e usa Euclides Estendido para calcular 
    // D como inverso modular de E
    // E*D <=> (mod(p-1)(q-1))
    public static BigInteger inversoModular(BigInteger e, BigInteger aux) {   
        
        ArrayList<BigInteger> ret = euclidesEstendido(e, aux);
 
        return ret.get(0).mod(aux);
    }
    
    // recebe dois BigInts
    // e retorna a tupla (u1, v1, a)
    // onde u1*a + v1*b = mdc(a,b)
    public static ArrayList<BigInteger> euclidesEstendido(BigInteger a, BigInteger b) {
        ArrayList<BigInteger> tupla = new ArrayList<>();
        
        BigInteger u = BigInteger.ZERO, v = BigInteger.ONE, 
        u1 = BigInteger.ONE, v1 = BigInteger.ZERO, aux;
        
        while(!b.equals(BigInteger.ZERO)) {
                BigInteger quociente = a.divide(b);
                BigInteger r = a.mod(b);
                
                aux = a;
                a = b;
                b = r;

                aux = u;
                u = u1.subtract(quociente.multiply(u));
                u1 = aux;

                aux = v;
                v = v1.subtract(quociente.multiply(v));
                v1 = aux;
        }
        BigInteger m = a;
        
        tupla.add(u1);
        tupla.add(v1);
        tupla.add(m);        
        
        return tupla;
    }
    
    // calcula num^exp mod n
    public static BigInteger expoenteModular(BigInteger num, BigInteger exp, BigInteger n) {
        BigInteger zero = new BigInteger("0");
        BigInteger um = new BigInteger("1");
        BigInteger dois = new BigInteger("2");
        
        
        if(exp.equals(zero)) {
            return um;
        } else {
            BigInteger res = expoenteModular(num, exp.divide(dois), n);
            res = res.multiply(res).mod(n);
            
            if (exp.mod(dois).equals(um)) {
                res = res.multiply(num).mod(n);
            }
            
            return res;
        }
    }
    
    // recebe a mensagem em BigInts e o número de bits que cada binario retornado terá
    // retorna um arraylist com as conversões, ignorando os casos "00000000"
    public static ArrayList<String> bigIntParaBinarios(ArrayList<BigInteger> mensagemBigInts, int qtdBits) {
        ArrayList<String> binariosFormatados = new ArrayList<>();
        String aux = new String();
        
        
        for (int i = 0; i < mensagemBigInts.size(); i++) {
            int inicio = 0;
            String binario = mensagemBigInts.get(i).toString(2);
            
            
            while (binario.length() < qtdBits*4) {
                binario = "0".concat(binario);
            }
            
            for (int j = 1; j <= binario.length(); j++) {
                
                if (j % qtdBits == 0 && j!=0) {
                    aux = binario.substring(inicio, j);
                    
                    if (!aux.equals("00000000")) {
                        binariosFormatados.add(aux);
                    }
                    
                    aux = "";
                    inicio += qtdBits;
                }
            }
        }
        System.out.println("bins: " + binariosFormatados);
        return binariosFormatados;
    }
    
    
    // recebe arraylist de ascii's
    // converte cada ascii pra char e concatena todos
    public static String asciiParaString(ArrayList<Integer> ascii) {
        String mensagem = new String();
        char aux;
        
        for (int i = 0; i < ascii.size(); i++) {     
            aux = (char) (ascii.get(i).intValue());
            mensagem = mensagem.concat(Character.toString(aux));
        }
        
        return mensagem;
    }
    
    // recebe um arraylist de binarios de 8 dígitos e 
    // faz a conversão simples para o decimal que representa o ascii de cada char
    public static ArrayList<Integer> binariosParaAscii(ArrayList<String> binarios) {
        ArrayList<Integer> ascii = new ArrayList<>();
        
        for (int i = 0; i < binarios.size(); i ++) {
            String binario = binarios.get(i);
            int acumulador = 0, potencia = 0, expoente = 0;
            
            for (int j = binario.length() - 1; j >= 0; j--) {
                
                if (binario.charAt(j) == '1') {
                    potencia = (int) Math.pow(2, expoente);
                    acumulador += potencia;
                }
                
                expoente++;
            }
            
            ascii.add(acumulador);
            
        }
       
        return ascii;
    }
    
    // calcula a raíz de um bigint
    public static BigInteger raizBigInt(BigInteger m) {
        BigInteger a = new BigInteger("1");
        BigInteger b = new BigInteger(m.shiftRight(5).add(new BigInteger ("8")).toString());
        
        while(b.compareTo(a) >= 0) {
            BigInteger c = new BigInteger(a.add(b).shiftRight(1).toString());
            if(c.multiply(c).compareTo(m) > 0) b = c.subtract(BigInteger.ONE);
            else a = c.add(BigInteger.ONE);
        }
        
        return a.subtract(BigInteger.ONE);
    }
}

