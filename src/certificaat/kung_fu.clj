(ns certificaat.kung-fu
  (:require [certificaat.util.configuration :as c]
            [certificaat.acme4j.authorization :as h]
            [certificaat.acme4j.session :as s]
            [certificaat.acme4j.challenge :as l]
            [certificaat.acme4j.account :as a]
            [certificaat.acme4j.registration :as r]
            [certificaat.acme4j.certificate :as t]
            [clojure.string :as str]
            [clojure.java.io :as io]
            [clojure.tools.logging :as log])
  (:import [org.shredzone.acme4j.exception AcmeUnauthorizedException]
           [java.net URI]))

(defn setup [{config-dir :config-dir domain :domain key-type :key-type key-size :key-size keypair-filename :keypair-filename}]
  (let [keypair (a/keypair key-type key-size)
        domain-keypair (a/keypair key-type key-size)]
    (c/create-dir config-dir)
    (c/add-keypair config-dir keypair-filename keypair)
    (c/add-keypair config-dir (str domain "-keypair.pem") domain-keypair)))

(defn session [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri}]
  (let [keypair (a/restore config-dir keypair-filename)]
    (s/create keypair acme-uri)))

(defn register [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri contact :contact :as options}]
  (let [registration-filename (io/file (str config-dir "registration.uri"))]
    (if (.exists registration-filename)
      (let [registration-uri (new URI (slurp registration-filename))
            session (session options)]
        (r/restore session registration-uri))
      (let [keypair (a/restore config-dir keypair-filename)
            reg (r/create keypair acme-uri contact)]
        (c/save-agreement config-dir reg)
        (r/accept-agreement reg)
        (spit (str config-dir "registration.uri") (.getLocation reg))
        reg))))

(defn authorize [{config-dir :config-dir domain :domain san :san challenges :challenges} reg]
  (let [domains (if san
                  (conj san domain)
                  [domain])]
    (for [domain domains
          :let [auth (h/create domain reg)]]
      [domain (l/find auth challenges)])))

(defn challenge [{config-dir :config-dir :as options}]
  (let [session (session options) 
        frozen-challenges (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file config-dir)))]
    (for [frozen-challenge frozen-challenges
          :let [uri (new URI (slurp frozen-challenge))
                challenge (l/restore session uri)]]
      (l/accept challenge))))

(defn request [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri domain :domain organisation :organisation san :san} reg]
  (let [domain-keypair (a/restore config-dir (str domain "-keypair.pem"))
        csrb (t/prepare domain-keypair domain organisation (when san san))
        cert ()]
    (t/persist-certificate-request csrb config-dir domain)
    (try (->> (t/request csrb reg)
              (t/persist config-dir))
         (catch AcmeUnauthorizedException e
           (log/error (.getMessage e))))))

(defn info [{config-dir :config-dir}]
  (try
    (t/check-expiry config-dir)
    (catch java.io.FileNotFoundException e (.getMessage e))))

(def explain l/explain)
