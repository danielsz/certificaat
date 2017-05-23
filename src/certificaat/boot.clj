(ns certificaat.boot
  (:require [clojure.core.async :refer [<!!]]
            [clojure.tools.logging :as log]
            [certificaat.domain :as d]
            [certificaat.configuration :as c]
            [certificaat.authorization :as h]
            [certificaat.session :as s]
            [certificaat.challenge :as l]
            [certificaat.account :as a]
            [certificaat.registration :as r]
            [certificaat.certificate :as t]
            [boot.core :as boot :refer [deftask with-pre-wrap]]
            [boot.util :as util]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import java.net.URI
           [org.shredzone.acme4j Status]))


(deftask certificaat-setup
  "Certificaat setup. Will create the configuration directory and create the account keys."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   m domain DOMAIN str "The domain you wish to authorize"
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
              keypair (a/keypair key-type key-size)
              domain-keypair (a/keypair key-type key-size)]
          (c/create-dir config-dir)
          (c/add-keypair config-dir keypair-filename keypair)
          (c/add-keypair config-dir (str domain "-keypair.pem") domain-keypair)))
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
    (fn [next-task]
      (fn [fileset] 
        (condp #(isa? %2 %1) (type input)
          Throwable (let [e input]
                      (if (= "Invalid input" (.getMessage e))
                        (log/error (ex-data e))
                        (util/fail (*usage*)))
                      e)
          (let [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri acme-contact :acme-contact} input 
                keypair (a/restore config-dir keypair-filename)
                registration (r/create keypair acme-uri acme-contact)
                tmp (boot/tmp-dir!)]
            (spit (str config-dir "registration.uri") (.getLocation registration))
            (spit (io/file tmp "registration.uri") (.getLocation registration))
            (next-task (-> fileset (boot/add-resource tmp) boot/commit!))))))))

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
    (fn [next-task]
      (fn [fileset] 
        (condp #(isa? %2 %1) (type input)
          Throwable (let [e input]
                      (if (= "Invalid input" (.getMessage e))
                        (log/error (ex-data e))
                        (util/fail (*usage*)))
                      e)
          (let [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri domain :domain challenges :challenges} input 
                keypair (a/restore config-dir keypair-filename)
                registration-uri (new URI (slurp (or
                                                  (some-> (boot/tmp-get fileset "registration.uri")
                                                          boot/tmp-file)
                                                  (str config-dir "registration.uri"))))
                session (s/create keypair acme-uri)
                reg (r/restore session registration-uri)
                auth (h/create domain reg)
                challenges (l/find auth challenges)
                tmp (boot/tmp-dir!)]
            (doseq [challenge challenges
                    i (range (count challenges))]
              (l/display challenge domain)
              (spit (str config-dir "challenge." domain "." i ".uri") (.getLocation challenge))
              (spit (io/file tmp (str "challenge." domain "." i ".uri")) (.getLocation challenge)))
            (next-task (-> fileset (boot/add-resource tmp) boot/commit!))))))))

(deftask certificaat-challenge
  "Certificaat will attempt to complete all challenges."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :keypair-filename "acme-account-keypair.pem"
                  :acme-uri "acme://letsencrypt.org/staging"}
        input (try
                (d/validate ::d/certificaat-challenge (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type input)
        Throwable (let [e input]
                    (if (= "Invalid input" (.getMessage e))
                      (log/error (ex-data e))
                      (util/fail (*usage*)))
                    e)
        (let [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri} input
              keypair (a/restore config-dir keypair-filename)
              session (s/create keypair acme-uri)
              frozen-challenges (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file config-dir)))]
          (doseq [frozen-challenge frozen-challenges
                  :let [uri (new URI (slurp frozen-challenge))
                        challenge (l/restore session uri)]]
            (if (= Status/VALID (<!! (l/accept challenge)))
              (util/info "Well done, you've succcessfully associated your domain with your account. You can now retrieve your certificate.")
              (util/warn "Sorry, something went wrong")))))
      fileset)))

(deftask certificaat-request
  "Certificaat will request the certificate and save in the configuration directory."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."
   m domain DOMAIN str "The domain you wish to authorize"
   o organisation ORGANISATION str "The organisation you with to register with the cerfiticate"
   a additional-domains DOMAINS [str] "Additional domains you already authorized with your account"]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :keypair-filename "acme-account-keypair.pem"
                  :acme-uri "acme://letsencrypt.org/staging"}
        input (try
                (d/validate ::d/certificaat-request (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type input)
        Throwable (let [e input]
                    (if (= "Invalid input" (.getMessage e))
                      (log/error (ex-data e))
                      (util/fail (*usage*)))
                    e)
        (let [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri domain :domain organisation :organisation} input 
              keypair (a/restore config-dir keypair-filename)
              domain-keypair (a/restore config-dir (str domain "-keypair.pem"))
              registration-uri (new URI (slurp (or
                                                (some-> (boot/tmp-get fileset "registration.uri")
                                                        boot/tmp-file)
                                                  (str config-dir "registration.uri"))))
              session (s/create keypair acme-uri)
              reg (r/restore session registration-uri)
              csrb (t/prepare domain-keypair domain organisation)
              cert (t/request csrb reg)]
          (t/persist-certificate-request csrb config-dir domain)
          (t/persist config-dir cert)))
      fileset)))

(deftask certificaat-renew []
  (with-pre-wrap fileset
    (util/info "hello world")
    fileset))

(deftask certificaat-info []
  (with-pre-wrap fileset
    (util/info "hello world")
    fileset))

(deftask polo []
  (comp
   (certificaat-setup :domain "teamsocial.me")
   (certificaat-register :acme-contact "mailto:daniel.szmulewicz@gmail.com")
   (certificaat-authorize :domain "teamsocial.me" :challenges #{"dns-01"})))

(deftask kolo []
  (comp
   (certificaat-challenge)
   (certificaat-request :domain "teamsocial.me" :organisation "Sapiens Sapiens")))
