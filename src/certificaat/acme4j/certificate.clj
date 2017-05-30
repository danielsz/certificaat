(ns certificaat.acme4j.certificate
  (:require [certificaat.acme4j.account :as account]
            [certificaat.acme4j.registration :as registration]
            [environ.core :refer [env]]
            [clojure.java.io :as io])
  (:import [org.shredzone.acme4j Certificate]
           [org.shredzone.acme4j.util CSRBuilder CertificateUtils]
           [org.shredzone.acme4j.util KeyPairUtils]
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

(defn persist-certificate-request [path csrb]
  (let [fw (FileWriter. (str path "request.csr"))]
    (.write csrb fw)))

(defn load-certificate-request [path]
  (let [input (io/input-stream (str path "request.csr"))]
    (CertificateUtils/readCSR input)))

(defn request [csrb reg]
  (.requestCertificate reg (.getEncoded csrb)))

(defn download [cert]
  [(.download cert) (.downloadChain cert)])

(defn persist [path cert]
  (let [[cert chain] (download cert)
        fw (FileWriter. (str path "domain-chain.crt"))]
    (CertificateUtils/writeX509CertificateChain fw cert chain)))

(defn delete [cert]
  (.revoke cert))

(defn restore [session uri]
  (Certificate/bind session uri))

(defn revoke [cert]
  (.revoke cert))

(defn match?
  "Utility function to determine if a private key matches a certificate"
  [cert key]
  (= (.getModulus (.getPublicKey cert)) (.getModulus (.getPrivate key))))

(defn info [path]
  (let [cert-file (str path "domain-chain.crt")
        key-file (str path "domain.key")
        cert (CertificateUtils/readX509Certificate (io/input-stream cert-file))
        issuer (.getIssuerX500Principal cert)
        subject (.getSubjectX500Principal cert)
        info {:issuer (.getName issuer)
              :subject (.getName subject)
              :san (map str (seq (.getSubjectAlternativeNames cert)))
              :valid-until (.getNotAfter cert)
              :path cert-file}]
    (if (.exists (io/file key-file))
      (let [key (KeyPairUtils/readKeyPair (FileReader. key-file))]
        (if (match? cert key)
          (assoc info :private-key key-file)
          info))
      info)))


