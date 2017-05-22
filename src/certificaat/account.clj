(ns certificaat.account
  (:require [environ.core :refer [env]])
  (:import [org.shredzone.acme4j.util KeyPairUtils]
           [java.security Security]
           [org.bouncycastle.jce.provider BouncyCastleProvider]
           [java.io FileWriter FileReader]))

(Security/addProvider (new org.bouncycastle.jce.provider.BouncyCastleProvider))

(defn keypair [& {:keys [key-type key-size] :or {key-type :rsa key-size 2048}}]
  (let [keypair (case key-type
                  :rsa (KeyPairUtils/createKeyPair key-size)
                  :ec (KeyPairUtils/createECKeyPair "secp256r1"))]
    keypair))

(defn persist [keypair path]
  (let [fw (FileWriter. path)]
    (KeyPairUtils/writeKeyPair keypair fw)))

(defn load [path]
  (let [fr (FileReader. path)]
    (KeyPairUtils/readKeyPair fr)))
