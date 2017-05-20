(ns certificaat.account
  (:require [environ.core :refer [env]])
  (:import [org.shredzone.acme4j.util KeyPairUtils]
           [java.security Security]
           [org.bouncycastle.jce.provider BouncyCastleProvider]
           [java.io FileWriter FileReader]))

(Security/addProvider (new org.bouncycastle.jce.provider.BouncyCastleProvider))

(defn keypair [& {:keys [type] :or {type :rsa}}]
  {:pre [(some #{type} [:rsa :ec])]}
  (let [keypair (case type
                  :rsa (KeyPairUtils/createKeyPair 2048)
                  :ec (KeyPairUtils/createECKeyPair "secp256r1"))]
    keypair))

(defn persist
  ([] (let [keypair (keypair)
            path (str (:certificaat-config-dir env) (:certificaat-keypair-filename env))]
        (persist keypair path)))
  ([keypair path] (let [fw (FileWriter. path)]
                    (KeyPairUtils/writeKeyPair keypair fw))))

(defn load
  ([] (load (str (:certificaat-config-dir env) (:certificaat-keypair-filename env))))
  ([path] (let [fr (FileReader. path)]
            (KeyPairUtils/readKeyPair fr))))


