(ns certificaat.certificate
  (:require [certificaat.account :as account]
            [certificaat.registration :as registration]
            [environ.core :refer [env]]
            [clojure.java.io :as io])
  (:import [org.shredzone.acme4j.util CSRBuilder CertificateUtils]
           [java.io FileWriter FileReader]))


(defn prepare []
  (let [keypair (account/load (str (:certificaat-config-dir env) (:certificaat-domain-keypair-filename env)))]
    (doto (CSRBuilder.)
      (.addDomain (:certificaat-domain env))
      (.setOrganization "Sapiens Sapiens")
      (.sign keypair))))

(defn persist-certificate-request [csrb]
  (let [fw (FileWriter. (str (:certificaat-config-dir env) (:certificaat-domain env) ".csr"))]
    (.write csrb fw)))

(defn load-certificate-request []
  (let [input (io/input-stream (str (:certificaat-config-dir env) (:certificaat-domain env) ".csr"))]
    (CertificateUtils/readCSR input)))

(defn request [csrb]
  (.requestCertificate (registration/create) (.getEncoded csrb)))

(defn download [cert]
  [(.download cert) (.downloadChain cert)])

(defn persist []
  (let [[cert chain] (download (request (prepare)))
        fw (FileWriter. (str (:certificaat-config-dir env) "cert-chain.crt"))]
    (CertificateUtils/writeX509CertificateChain fw cert chain)))

(defn delete [cert]
  (.revoke cert))

(defn check-expiry []
  (let [cert (io/input-stream (str (:certificaat-config-dir env) "cert-chain.crt"))]
    (.getNotAfter (CertificateUtils/readX509Certificate cert))))
