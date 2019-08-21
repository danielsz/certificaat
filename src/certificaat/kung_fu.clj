(ns certificaat.kung-fu
  (:require
   [certificaat.acme4j.keypair :as keypair]
   [certificaat.acme4j.account :as account]
   [certificaat.acme4j.order :as order]
   [certificaat.acme4j.authorization :as authorization]
   [certificaat.acme4j.certificate :as certificate]
   [certificaat.acme4j.challenge :as challenge]
   [certificaat.acme4j.registration :as registration]
   [certificaat.acme4j.session :as session]
   [certificaat.utils :refer [exit]]
   [certificaat.util.configuration :as c]
   [certificaat.domain :as d]
   [clj-http.client :as client]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [clojure.tools.logging :as log]
   [clojure.spec.alpha :as s]
   [clj-http.client :as client])
  (:import java.net.URI
           org.shredzone.acme4j.exception.AcmeUnauthorizedException
           org.shredzone.acme4j.Status))

(defn session [{:keys [acme-uri]}]
  (session/create acme-uri))

(defn valid? [frozen-resource options]
  (let [session (session options)]
    (condp s/valid? (.getName (io/as-file frozen-resource))
      ::d/registration-uri (if-let [registration-uri (c/load-url frozen-resource)]
                            (let [registration (registration/restore session registration-uri)]
                              (d/valid? registration)))
      ::d/authorization-uri (if-let [authorization-uri (c/load-url frozen-resource)]
                              (let [authorization (authorization/restore session authorization-uri)]
                                (d/valid? authorization)))
      ::d/certificate-uri (if-let [certificate-uri (c/load-url frozen-resource)]
                           (let [certificate (certificate/restore session certificate-uri)]
                             (d/valid? certificate))))))

(defn setup [{:keys [config-dir domain key-type key-size keypair-filename] :as options}]
  (let [account-keypair (keypair/create key-type key-size)
        domain-keypair (keypair/create key-type key-size)
        account-path (str config-dir keypair-filename) 
        domain-path (str config-dir domain "/domain.key")]
    (c/add-keypair account-path account-keypair)
    (c/add-keypair domain-path domain-keypair)
    (c/add-config options)))


(defn login [session account-uri keypair]
  (.login session account-uri keypair))

(defn account [{:keys [config-dir keypair-filename acme-uri contact] :as options}]
  (if-let [account-uri (c/load-url (str config-dir "account.url"))]
    (let [session (session/create acme-uri)
          keypair (keypair/read config-dir keypair-filename)]
      (account/read session keypair))
    (let [session (session/create acme-uri)
          keypair (keypair/read config-dir keypair-filename)
          account (account/create session keypair contact)]
      (spit (str config-dir "account.url") (.getLocation account))
      account)))

(defn order [account {:keys [config-dir domain san challenges]}]
  (let [domains (if san
                  (conj san domain)
                  [domain])]
    (order/create account (str/join " " domains))))

(defn authorize [order]
  (doseq [authorization (.getAuthorizations order)]
    (when (valid? authorization)
      ;(process authorization)
      )))

(defn authorize [{:keys [config-dir domain san challenges]} reg]
  (let [domains (if san
                  (conj san domain)
                  [domain])]
    (for [domain domains
          :let [auth (authorization/create domain reg)]]
      [domain auth (challenge/find auth challenges)])))

(defn challenge [{domain :domain config-dir :config-dir :as options}]
  (let [session (session options) 
        frozen-challenges (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file (str config-dir domain))))
        challenges (for [frozen-challenge frozen-challenges
                         :let [uri (new URI (slurp frozen-challenge))]]
                     (challenge/restore session uri))]
    (doseq [challenge challenges]
      (when (= "http-01" (.getType challenge))
        (try (client/head (str "http://" domain  "/.well-known/acme-challenge/" (.getToken challenge)))
             (catch Exception e (exit 1 (str "Please make sure you can respond to the challenges.\nError message: " (.getMessage e))))))) ;precheck
    (for [challenge challenges]
      (challenge/accept challenge))))

(defn pending? [frozen-resource options]
  (let [session (session options)
        authorization-uri (c/load-url frozen-resource)
        authorization (authorization/restore session authorization-uri)]
    (= Status/PENDING (.getStatus authorization))))

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

(def explain challenge/explain)

(defn register [x])

(defn info [x])
