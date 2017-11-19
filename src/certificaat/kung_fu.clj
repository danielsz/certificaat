(ns certificaat.kung-fu
  (:require [certificaat.acme4j.account :as account]
            [certificaat.acme4j.authorization :as authorization]
            [certificaat.acme4j.certificate :as certificate]
            [certificaat.acme4j.challenge :as challenge]
            [certificaat.acme4j.registration :as registration]
            [certificaat.acme4j.session :as session]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [certificaat.util.configuration :as c])
  (:import java.net.URI
           org.shredzone.acme4j.exception.AcmeUnauthorizedException))

(defn setup [{:keys [config-dir domain key-type key-size keypair-filename] :as options}]
  (let [account-keypair (account/keypair key-type key-size)
        domain-keypair (account/keypair key-type key-size)
        account-path (str config-dir keypair-filename) 
        domain-path (str config-dir domain "/domain.key")]
    (c/add-keypair account-path account-keypair)
    (c/add-keypair domain-path domain-keypair)
    (c/add-config options)))

(defn session [{:keys [config-dir keypair-filename acme-uri]}]
  (let [keypair (account/restore config-dir keypair-filename)]
    (session/create keypair acme-uri)))

(defn register [{:keys [config-dir keypair-filename acme-uri contact] :as options}]
  (let [frozen-registration (io/file (str config-dir "registration.uri"))]
    (if (.exists frozen-registration)
      (let [registration-uri (new URI (slurp frozen-registration))
            session (session options)]
        (registration/restore session registration-uri))
      (let [keypair (account/restore config-dir keypair-filename)
            reg (registration/create keypair acme-uri contact)]
        (c/save-agreement config-dir reg)
        (registration/accept-agreement reg)
        (spit (str config-dir "registration.uri") (.getLocation reg))
        reg))))

(defn authorize [{:keys [config-dir domain san challenges]} reg]
  (let [domains (if san
                  (conj san domain)
                  [domain])]
    (for [domain domains
          :let [auth (authorization/create domain reg)]]
      [domain auth (challenge/find auth challenges)])))

(defn authorize2 [{:keys [config-dir domain san challenges] :as options}]
  (let [session (session options)
        domains (if san
                  (conj san domain)
                  [domain])]
    (doseq [domain domains
            :let [frozen-authorization (str config-dir domain "/authorization." domain ".uri")
                  uri (new URI (slurp frozen-authorization))
                  auth (authorization/restore session uri)]]
      (println (.getDomain auth))
      (println (.getStatus auth))
      (println (.getExpires auth)))))

(defn challenge [{domain :domain config-dir :config-dir :as options}]
  (let [session (session options) 
        frozen-challenges (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file (str config-dir domain))))]
    (for [frozen-challenge frozen-challenges
          :let [uri (new URI (slurp frozen-challenge))
                challenge (challenge/restore session uri)]]
      (challenge/accept challenge))))

(defn get-certificate [{:keys [config-dir domain organisation san] :as options} reg]
  (let [path (str config-dir domain "/")
        csr (str path "request.csr")]
    (if (.exists (io/file csr))
      (let [csrb (certificate/load-certificate-request csr)]
        (certificate/request csrb reg))
      (let [domain-keypair (account/restore path "domain.key")
            csrb (certificate/prepare domain-keypair domain organisation (when san san))]
        (certificate/persist-certificate-request csr csrb)
        (certificate/request csrb reg)))))

(defn request [{config-dir :config-dir domain :domain :as options} reg]
  (let [path (str config-dir domain "/")
        cert (get-certificate options reg)]
    (certificate/persist (str path "domain-chain.crt") cert)
    (spit (str path "certificate.uri") (.getLocation cert))
    (log/info "Well done! You will find your certificate chain in" path)))

(defn info [{config-dir :config-dir domain :domain}]
  (let [path (str config-dir domain "/")
        cert-file (str path "domain-chain.crt")
        key-file (str path "domain.key")]
    (certificate/info cert-file key-file)))

(def explain challenge/explain)
