(ns certificaat.kung-fu
  (:require [certificaat.acme4j.account :as account]
            [certificaat.acme4j.authorization :as authorization]
            [certificaat.acme4j.certificate :as certificate]
            [certificaat.acme4j.challenge :as challenge]
            [certificaat.acme4j.registration :as registration]
            [certificaat.acme4j.session :as session]
            [certificaat.util.configuration :as configuration]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.logging :as log])
  (:import java.net.URI
           org.shredzone.acme4j.exception.AcmeUnauthorizedException))

(defn setup [{config-dir :config-dir domain :domain key-type :key-type key-size :key-size keypair-filename :keypair-filename}]
  (let [keypair (account/keypair key-type key-size)
        domain-keypair (account/keypair key-type key-size)
        domain-path (str config-dir domain "/")]
    (io/make-parents (str domain-path "domain.key"))
    (configuration/add-keypair config-dir keypair-filename keypair)
    (configuration/add-keypair domain-path "domain.key" domain-keypair)))

(defn session [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri}]
  (let [keypair (account/restore config-dir keypair-filename)]
    (session/create keypair acme-uri)))

(defn register [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri contact :contact :as options}]
  (let [frozen-registration (io/file (str config-dir "registration.uri"))]
    (if (.exists frozen-registration)
      (let [registration-uri (new URI (slurp frozen-registration))
            session (session options)]
        (registration/restore session registration-uri))
      (let [keypair (account/restore config-dir keypair-filename)
            reg (registration/create keypair acme-uri contact)]
        (configuration/save-agreement config-dir reg)
        (registration/accept-agreement reg)
        (spit (str config-dir "registration.uri") (.getLocation reg))
        reg))))

(defn authorize [{config-dir :config-dir domain :domain san :san challenges :challenges} reg]
  (let [domains (if san
                  (conj san domain)
                  [domain])]
    (for [domain domains
          :let [auth (authorization/create domain reg)]]
      [domain (challenge/find auth challenges)])))

(defn challenge [{domain :domain config-dir :config-dir :as options}]
  (let [session (session options) 
        frozen-challenges (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file (str config-dir domain))))]
    (for [frozen-challenge frozen-challenges
          :let [uri (new URI (slurp frozen-challenge))
                challenge (challenge/restore session uri)]]
      (challenge/accept challenge))))

(defn get-certificate [{config-dir :config-dir domain :domain organisation :organisation san :san :as options} reg]
  (let [path (str config-dir domain "/")
        frozen-certificate (io/file (str path "certificate.uri"))]
    (if (.exists frozen-certificate)
      (let [certificate-uri (new URI (slurp frozen-certificate))
            session (session options)]
        (certificate/restore session certificate-uri))
      (let [domain-keypair (account/restore path "domain.key")
            csrb (certificate/prepare domain-keypair domain organisation (when san san))
            cert (certificate/request csrb reg)]
        (certificate/persist-certificate-request path csrb)
        (spit (str path "certificate.uri") (.getLocation cert))
        cert))))

(defn request [{config-dir :config-dir domain :domain :as options} reg]
  (let [path (str config-dir domain "/")
        cert (get-certificate options reg)]
    (try (certificate/persist path cert)
         (catch AcmeUnauthorizedException e
           (log/error (.getMessage e))))
    (log/info "Well done! You will find your certificate chain in" path)))

(defn renew [{domain :domain config-dir :config-dir :as options}]
  (let [path (str config-dir domain "/")
        reg (register options)
        csrb (certificate/load-certificate-request path)
        cert (certificate/request csrb reg)]
    (spit (str path "certificate.uri") (.getLocation cert))
    (try (certificate/persist path cert)
         (catch AcmeUnauthorizedException e
           (log/error (.getMessage e))))
    (log/info "Well done! You will find your certificate chain in" path)))

(defn info [{config-dir :config-dir domain :domain}]
  (let [path (str config-dir domain "/")]
    (try
      (certificate/info path)
      (catch java.io.FileNotFoundException e (.getMessage e)))))

(def explain challenge/explain)
