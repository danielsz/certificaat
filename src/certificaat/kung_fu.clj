(ns certificaat.kung-fu
  (:require
   [certificaat.acme4j.session :as session]
   [certificaat.acme4j.keypair :as keypair]
   [certificaat.acme4j.account :as account]
   [certificaat.acme4j.challenge :as challenge]
   [certificaat.acme4j.order :as order]
   [certificaat.acme4j.authorization :as authorization]
   [certificaat.acme4j.certificate :as certificate]
   [certificaat.utils :refer [exit load-url]]
   [certificaat.domain :as d]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [clojure.tools.logging :as log]
   [clojure.spec.alpha :as s]
   [clojure.core.async :refer [<!!]])
  (:import java.net.URI
           org.shredzone.acme4j.exception.AcmeUnauthorizedException
           org.shredzone.acme4j.Status))

(defn restore [path {:keys [config-dir keypair-filename acme-uri] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)]
    (condp s/valid? (.getName (io/as-file path))
      ::d/account-url (when (.exists (io/file path))
                        (account/restore session keypair))
      ::d/order-url (when (.exists (io/file path))
                      (order/restore login path))
      ::d/authorization-url (when (.exists (io/file path))
                              (authorization/restore login path))
      ::d/certificate-url (when (.exists (io/file path))
                           (certificate/restore login path)))))

(defn valid? [path options]
  (when-let [resource (restore path options)]
    (d/valid? resource)))

(defn invalid? [path options]
  (when-let [resource (restore path options)]
    (d/invalid? resource)))

(defn ready? [path options]
  (when-let [resource (restore path options)]
    (d/ready? resource)))

(defn pending? [path options]
  (when-let [resource (restore path options)]
    (d/pending? resource)))

(defn account [{:keys [config-dir keypair-filename acme-uri contact] :as options}]
  (if-let [account-url (load-url (str config-dir "account.url"))]
    (let [session (session/create acme-uri)
          keypair (keypair/read config-dir keypair-filename)]
      (account/read session keypair))
    (let [session (session/create acme-uri)
          keypair (keypair/read config-dir keypair-filename)
          account (account/create session keypair contact :with-login false)]
      (d/marshal account (str config-dir "account.url"))
      account)))


(defn order [{:keys [config-dir keypair-filename acme-uri domain san] :as options}]
  (let [session (session/create acme-uri)
          keypair (keypair/read config-dir keypair-filename)
          account (account/restore session keypair)
          domains (if san (conj san domain) [domain])
          order-builder (doto (.newOrder account)
                          (.domains domains))
          order (order/create account domains)]
      (d/marshal order (str config-dir domain "/order.url"))))

(defn authorize [{:keys [config-dir keypair-filename acme-uri domain] :as options}]
  (let  [session (session/create acme-uri)
         keypair (keypair/read config-dir  keypair-filename)
         login (account/login (str (:config-dir options) "/account.url") keypair session)
         order (order/restore login (str (:config-dir options) (:domain options) "/order.url"))]
    (doseq [auth (.getAuthorizations order)
            :when (not (.isWildcard auth))]
      (d/marshal auth (str (:config-dir options) (:domain options) "/authorization." (.getDomain (.getIdentifier auth)) ".url")))))

(defn challenge [{:keys [config-dir keypair-filename acme-uri domain] :as options}]
  (let  [session (session/create acme-uri)
         keypair (keypair/read config-dir keypair-filename)
         login (account/login (str config-dir "account.url") keypair session)
         order (order/restore login (str config-dir domain "/order.url"))]
    (doseq [auth (.getAuthorizations order)
            :let [challenge (challenge/find auth (first (:challenges options)))
                  domain (.getDomain (.getIdentifier auth))]]
      (d/marshal challenge (str config-dir (:domain options) "/challenge." domain ".url"))
      (println (challenge/explain challenge (.getDomain (.getIdentifier auth)))))))


(defn get-challenges [{:keys [domain config-dir acme-uri keypair-filename] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)
        order (order/restore login (str config-dir domain "/order.url"))]
    (for [auth (.getAuthorizations order)
          :let [challenge (challenge/find auth (first (:challenges options)))]]
      challenge)))

(defn accept-challenges [{:keys [domain config-dir acme-uri keypair-filename] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)
        order (order/restore login (str config-dir domain "/order.url"))]     
    (doseq [auth (.getAuthorizations order)
            :let [challenge (challenge/find auth (first (:challenges options)))]]
      (log/debug "Channel returned:" (<!! (challenge/accept challenge))))))


(defn finalize-order [{:keys [domain config-dir acme-uri keypair-filename] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)
        order (order/restore login (str config-dir domain "/order.url"))
        domain-keypair (keypair/read (str config-dir domain "/domain.key"))
        csrb (certificate/prepare domain-keypair domain (:organisation options))
        csr (.getEncoded csrb)]
    (certificate/persist-certificate-request csrb (str config-dir domain "/cert.csr")) 
    (.execute order csr)))


(defn get-certificate [{:keys [domain config-dir acme-uri keypair-filename] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)
        order (order/restore login (str config-dir domain "/order.url"))
        cert (.getCertificate order)
        X509Certificate (.getCertificate cert)
        chain (.getCertificateChain cert)]
    (certificate/persist cert (str config-dir domain "/cert-chain.crt"))
    (.checkValidity X509Certificate)
    (d/marshal cert (str config-dir domain "/cert.url"))
    (log/info "Well done! You will find your certificate chain in" (str config-dir domain "/"))))

(defn hooks-enabled? [hooks]
  (some (fn [[k v]] (:enabled v)) hooks))

