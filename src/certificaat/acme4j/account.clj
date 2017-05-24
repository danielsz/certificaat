(ns certificaat.acme4j.account
  (:require [environ.core :refer [env]]
            [clojure.tools.logging :as log])
  (:import [org.shredzone.acme4j.util KeyPairUtils]
           [java.security Security]
           [org.bouncycastle.jce.provider BouncyCastleProvider]
           [java.io FileWriter FileReader]))

(Security/addProvider (new org.bouncycastle.jce.provider.BouncyCastleProvider))

(defn keypair [key-type key-size]
  (let [keypair (case key-type
                  :rsa (KeyPairUtils/createKeyPair key-size)
                  :ec (KeyPairUtils/createECKeyPair "secp256r1"))]
    keypair))

(defn persist [keypair path]
  (let [fw (FileWriter. path)]
    (KeyPairUtils/writeKeyPair keypair fw)))

(defn restore
  ([path]
   (let [fr (FileReader. path)]
     (KeyPairUtils/readKeyPair fr)))
  ([config-dir keypair-filename]
   (restore (str config-dir keypair-filename))))
