(ns certificaat.interface.boot
  (:require [clojure.core.async :refer [<!!]]
            [clojure.tools.logging :as log]
            [certificaat.domain :as d]
            [certificaat.util.configuration :as c]
            [certificaat.acme4j.authorization :as h]
            [certificaat.acme4j.session :as s]
            [certificaat.acme4j.challenge :as l]
            [certificaat.acme4j.account :as a]
            [certificaat.acme4j.registration :as r]
            [certificaat.acme4j.certificate :as t]
            [boot.core :as boot :refer [deftask with-pre-wrap]]
            [boot.util :as util]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import java.net.URI
           [org.shredzone.acme4j Status]))

(deftask certificaat-setup
  "Certificaat setup. Will create the configuration directory and create the account keys."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file used to register the ACME account."
   m domain DOMAIN str "The domain you wish to authorize"
   t key-type KEY-TYPE kw "The key type, one of RSA or Elliptic Curve."
   s key-size KEY-SIZE int "Key length used to create a RSA private key."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/" domain "/")
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
                      (*usage*))
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
   m domain DOMAIN str "The domain you wish to authorize"
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."
   c contact CONTACT str "The email address used to send you expiry notices (mailto:me@example.com)"]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/" domain "/")
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
                        (*usage*))
                      e)
          (let [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri contact :contact} input 
                keypair (a/restore config-dir keypair-filename)
                registration (r/create keypair acme-uri contact)
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
   c challenges CHALLENGES #{str} "The challenges you can complete"
   s san SAN #{str} "Subject Alternative Name (SAN). Additional domains to be authorized."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/" domain "/")
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
                        (*usage*))
                      e)
          (let [{config-dir :config-dir
                 keypair-filename :keypair-filename
                 acme-uri :acme-uri
                 domain :domain
                 san :san
                 challenges :challenges} input 
                keypair (a/restore config-dir keypair-filename)
                registration-uri (new URI (slurp (or
                                                  (some-> (boot/tmp-get fileset "registration.uri")
                                                          boot/tmp-file)
                                                  (str config-dir "registration.uri"))))
                session (s/create keypair acme-uri)
                reg (r/restore session registration-uri)
                tmp (boot/tmp-dir!)
                domains (if san
                          (conj san domain)
                          [domain])]
            (doseq [domain domains
                        :let [auth (h/create domain reg)
                              challenges (l/find auth challenges)]]                  
                  (doseq [challenge challenges
                          i (range (count challenges))
                          :let [explanation (l/explain challenge domain)]]
                    (util/info "%s\n" explanation)
                    (spit (str config-dir "challenge." domain "." (.getType challenge) ".txt") explanation)
                    (spit (io/file tmp (str "challenge." domain "." (.getType challenge) ".txt")) explanation)
                    (spit (str config-dir "challenge." domain "." i ".uri") (.getLocation challenge))
                    (spit (io/file tmp (str "challenge." domain "." i ".uri")) (.getLocation challenge))))
            (next-task (-> fileset (boot/add-resource tmp) boot/commit!))))))))

(deftask certificaat-challenge
  "Certificaat will attempt to complete all challenges."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   m domain DOMAIN str "The domain you wish to authorize"
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/" domain "/")
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
                      (*usage*))
                    e)
        (let [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri} input
              keypair (a/restore config-dir keypair-filename)
              session (s/create keypair acme-uri)
              frozen-challenges (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file config-dir)))]
          (doseq [frozen-challenge frozen-challenges
                  :let [uri (new URI (slurp frozen-challenge))
                        challenge (l/restore session uri)]]
            (if (= Status/VALID (<!! (l/accept challenge)))
              (util/info "Well done, you've succcessfully associated your domain with your account. You can now retrieve your certificate.\n")
              (util/warn "Sorry, something went wrong\n")))))
      fileset)))

(deftask certificaat-request
  "Certificaat will request the certificate and save in the configuration directory."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."
   m domain DOMAIN str "The domain you wish to authorize"
   o organisation ORGANISATION str "The organisation you with to register with the cerfiticate"
   s san SAN #{str} "Subject Alternative Name (SAN). Additional domains to be authorized."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/" domain "/")
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
                      (*usage*))
                    e)
        (let [{config-dir :config-dir
               keypair-filename :keypair-filename
               acme-uri :acme-uri
               domain :domain
               organisation :organisation
               san :san} input 
              keypair (a/restore config-dir keypair-filename)
              domain-keypair (a/restore config-dir (str domain "-keypair.pem"))
              registration-uri (new URI (slurp (or
                                                (some-> (boot/tmp-get fileset "registration.uri")
                                                        boot/tmp-file)
                                                  (str config-dir "registration.uri"))))
              session (s/create keypair acme-uri)
              reg (r/restore session registration-uri)
              csrb (t/prepare domain-keypair domain organisation (when san san))
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
    (*usage*)
    (util/info "hello world")
    fileset))

(deftask polo []
  (comp
   (certificaat-setup :domain "teamsocial.me")
   (certificaat-register :domain "teamsocial.me" :contact "mailto:daniel.szmulewicz@gmail.com")
   (certificaat-authorize :domain "teamsocial.me" :challenges #{"dns-01"} :san #{"www.teamsocial.me"})))

(deftask kolo []
  (comp
   (certificaat-challenge :domain "teamsocial.me")
   (certificaat-request :domain "teamsocial.me" :organisation "Sapiens Sapiens" :san #{"www.teamsocial.me"})))

(deftask molo []
  (with-pre-wrap fileset
    (util/info "hello world")
    (let [input (read-line)]
      (println input))
    fileset))
