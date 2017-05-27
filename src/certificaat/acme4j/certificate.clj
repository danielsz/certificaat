(ns certificaat.acme4j.certificate
  (:require [certificaat.acme4j.account :as account]
            [certificaat.acme4j.registration :as registration]
            [environ.core :refer [env]]
            [clojure.java.io :as io])
  (:import [org.shredzone.acme4j.util CSRBuilder CertificateUtils]
           [java.io FileWriter FileReader]))

(defn prepare [keypair domain organization & [additional-domains]]
  (let [builder (CSRBuilder.)]
    (.addDomain builder domain)
    (when additional-domains
      (doseq [domain additional-domains]
        (.addDomain builder domain)))
    (doto builder
      (.setOrganization organization)
      (.sign keypair))))

(defn persist-certificate-request [csrb config-dir domain]
  (let [fw (FileWriter. (str config-dir domain ".csr"))]
    (.write csrb fw)))

(defn load-certificate-request [config-dir domain]
  (let [input (io/input-stream (str config-dir domain ".csr"))]
    (CertificateUtils/readCSR input)))

(defn request [csrb reg]
  (.requestCertificate reg (.getEncoded csrb)))

(defn download [cert]
  [(.download cert) (.downloadChain cert)])

(defn persist [config-dir cert]
  (let [[cert chain] (download cert)
        fw (FileWriter. (str config-dir "cert-chain.crt"))]
    (CertificateUtils/writeX509CertificateChain fw cert chain)))

(defn delete [cert]
  (.revoke cert))

(defn check-expiry [config-dir]
  (let [cert (io/input-stream (str config-dir "cert-chain.crt"))]
    (.getNotAfter (CertificateUtils/readX509Certificate cert))))
