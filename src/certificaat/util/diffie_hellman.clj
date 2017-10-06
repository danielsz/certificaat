(ns certificaat.util.diffie-hellman
  (:import (java.security AlgorithmParameters AlgorithmParameterGenerator SecureRandom)
           javax.crypto.spec.DHParameterSpec
           java.io.FileWriter
           (org.bouncycastle.util.io.pem PemObject PemWriter)))

(defn generate-parameter-set [prime-size]
  (let [param-gen (AlgorithmParameterGenerator/getInstance "DH")
        _ (.init param-gen prime-size (SecureRandom.))
        params (.generateParameters param-gen)]
    (.getEncoded params)))

(defn save-to-pem [path params]
  (let [file (new FileWriter path)
        pem-writer (new PemWriter file)
        pem-object (new PemObject "DH PARAMETERS" params)]
    (doto pem-writer
      (.writeObject pem-object)
      (.flush)
      (.close))))
