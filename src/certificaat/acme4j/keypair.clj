(ns certificaat.acme4j.keypair
  (:refer-clojure :exclude [read])
  (:import
   [org.shredzone.acme4j.util KeyPairUtils]
   [java.security Security]
   [org.bouncycastle.jce.provider BouncyCastleProvider]
   [java.io FileWriter FileReader]))

(Security/addProvider (new org.bouncycastle.jce.provider.BouncyCastleProvider))

(defn create [key-type key-size]
  (let [keypair (case key-type
                  :rsa (KeyPairUtils/createKeyPair key-size)
                  :ec (KeyPairUtils/createECKeyPair "secp256r1"))]
    keypair))

(defn write [keypair path]
  (let [fw (FileWriter. path)]
    (KeyPairUtils/writeKeyPair keypair fw)))

(defn read
  ([path]
   (let [fr (FileReader. path)]
     (KeyPairUtils/readKeyPair fr)))
  ([config-dir keypair-filename]
   (read (str config-dir keypair-filename))))

