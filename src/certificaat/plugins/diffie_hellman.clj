(ns certificaat.plugins.diffie-hellman
  (:require [clojure.java.io :as io])
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

(defn group14-to-path [path]
  (let [group14 (slurp (io/resource "group14.pem"))]
    (spit path group14)))

(defn params [{{{group14 :group14 filename :filename modulus :modulus enabled :enabled} :diffie-hellman} :plugins domain :domain config-dir :config-dir :as options}]
  (when enabled
    (let [path (str config-dir domain "/" filename)
          file (io/file path)]
      (when (not (.exists file))
        (if group14
          (group14-to-path path)
          (save-to-pem path (generate-parameter-set modulus)))))))

