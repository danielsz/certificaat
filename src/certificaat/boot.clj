(ns certificaat.boot
  (:require [clojure.tools.logging :as log]
            [certificaat.domain :as d]
            [certificaat.configuration :as c]
            [certificaat.authorization :as h]
            [certificaat.session :as s]
            [certificaat.challenge :as l]
            [certificaat.account :as a]
            [certificaat.registration :as r]
            [boot.core :as boot :refer [deftask with-pre-wrap]]
            [boot.util :as util])
  (:import java.net.URI))


(deftask certificaat-setup
  "Certificaat setup. Will create the configuration directory and create the account keys."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   t key-type KEY-TYPE kw "The key type, one of RSA or Elliptic Curve."
   s key-size KEY-SIZE int "Key length used to create the private key used to register the ACME account."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :keypair-filename "acme-account-keypair.pem"
                  :key-type :rsa
                  :key-size 2048}
        input (try
                (d/validate ::d/certificaat-setup (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type input)
        Throwable (let [e input]
                    (if (= "Invalid input" (.getMessage e))
                      (log/error (ex-data e))
                      (util/fail (*usage*)))
                    e)
        (let [{config-dir :config-dir key-type :key-type key-size :key-size keypair-filename :keypair-filename} input 
              keypair (a/keypair key-type key-size)]
          (c/create-dir config-dir)
          (c/add-keypair config-dir keypair-filename keypair)))
      fileset)))

(deftask certificaat-register
  "Certificaat registration with ACME server. Will create the account, show the TOS, and save the registration URI."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."
   c acme-contact ACME-CONTACT str "mailto:daniel.szmulewicz@gmail.com"]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :keypair-filename "acme-account-keypair.pem"
                  :acme-uri "acme://letsencrypt.org/staging"}
        input (try
                (d/validate ::d/certificaat-register (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type input)
        Throwable (let [e input]
                    (if (= "Invalid input" (.getMessage e))
                      (log/error (ex-data e))
                      (util/fail (*usage*)))
                    e)
        (let [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri acme-contact :acme-contact} input 
              keypair (a/restore config-dir keypair-filename)
              registration (r/create keypair acme-uri acme-contact)]
          (spit (str config-dir "registration.uri") (.getLocation registration))))
      fileset)))

(deftask certificaat-authorize
  "Certificaat authorize a domain with ACME server. Will find a challenge and save the challenge URI."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."
   m domain DOMAIN str "The domain you wish to authorize"
   c challenges CHALLENGES #{str} "The challenges you can complete"]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :keypair-filename "acme-account-keypair.pem"
                  :acme-uri "acme://letsencrypt.org/staging"
                  :challenges #{"http-01"}}
        input (try
                (d/validate ::d/certificaat-authorize (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type input)
        Throwable (let [e input]
                    (if (= "Invalid input" (.getMessage e))
                      (log/error (ex-data e))
                      (util/fail (*usage*)))
                    e)
        (let [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri domain :domain challenges :challenges} input 
              keypair (a/restore config-dir keypair-filename)
              registration-uri (new URI (slurp (str config-dir "registration.uri")))
              session (s/create keypair acme-uri)
              reg (r/restore session registration-uri)
              auth (h/create domain reg)
              challenges (l/find2 auth challenges)]
          (doseq [challenge challenges
                  i (range (count challenges))]
            (spit (str config-dir "challenge" i ".uri") (.getLocation challenge)))))
      fileset)))


(deftask certificaat-challenge []
  (with-pre-wrap fileset
    (util/info "hello world")
    fileset))

(deftask certificaat-request [i info INFO edn "The info map for the certificate request"]
  (with-pre-wrap fileset
    (util/info "Requesting certificate")
    (log/info info)
    fileset))

(deftask certificaat-renew []
  (with-pre-wrap fileset
    (util/info "hello world")
    fileset))

(deftask certificaat-info []
  (with-pre-wrap fileset
    (util/info "hello world")
    fileset))
