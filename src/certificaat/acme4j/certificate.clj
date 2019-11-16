(ns certificaat.acme4j.certificate
  (:require [certificaat.domain :refer [Certificaat]]
            [certificaat.utils :refer [load-url]]
            [clojure.tools.logging :as log]
            [clojure.java.io :as io])
  (:import [org.shredzone.acme4j Certificate RevocationReason]
           [org.shredzone.acme4j.util KeyPairUtils CSRBuilder CertificateUtils]
           [java.security.cert CertificateExpiredException CertificateNotYetValidException CertificateFactory]
           [org.bouncycastle.util.io.pem PemReader]
           [java.io FileWriter FileReader ByteArrayInputStream]))

(defn prepare [keypair domains organization]
  (let [builder (CSRBuilder.)]
    (doseq [domain domains]
      (.addDomain builder domain))
    (doto builder
      (.setOrganization organization)
      (.sign keypair))))

(defn persist-certificate-request [csrb path]
  (let [fw (FileWriter. path)]
    (.write csrb fw)))

(defn load-certificate-request [path]
  (let [input (io/input-stream path)]
    (CertificateUtils/readCSR input)))

(defn persist [cert path]
  (let [fw (FileWriter. path)]
    (.writeCertificate cert fw)
    (.flush fw)))

(defn restore [login path]
  (.bindCertificate login (load-url path)))

(defn revoke
  ([cert]
   (.revoke cert))
  ([cert reason]
   (.revoke cert reason))
  ([login cert reason]
   (Certificate/revoke login cert reason))
  ([session domain-keypair cert reason]
   (Certificate/revoke session domain-keypair cert reason)))

(defn match?
  "Utility function to determine if a private key matches a certificate"
  [cert key]
  (= (.getModulus (.getPublicKey cert)) (.getModulus (.getPrivate key))))

(defn read-csr [file]
  (CertificateUtils/readCSR (io/input-stream file)))

(defn read-pem [file]
  (let [crt (FileReader. file)
        x509data (.getContent (.readPemObject (PemReader. crt)))
        factory (CertificateFactory/getInstance "X509")]
    (.generateCertificate factory (ByteArrayInputStream. x509data))))

(defn info
  ([{config-dir :config-dir domain :domain}]
   (let [path (str config-dir domain "/")
         cert-file (str path "cert-chain.crt")
         key-file (str path "domain.key")]
    (info cert-file key-file)))
  ([cert-file key-file]
   (let [cert (read-pem cert-file)
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
       info))))


(extend-type Certificate
  Certificaat
  (valid? [this] (let [X509Certificate (.getCertificate this)]
                   (log/info "Certificate expires after" (.getNotAfter X509Certificate))
                   (try (.checkValidity X509Certificate)
                        true
                        (catch CertificateExpiredException e false)
                        (catch CertificateNotYetValidException e false))))
  (marshal [this path]
    (spit path (.getLocation this))))
