(ns certificaat.boot
  (:require [clojure.tools.logging :as log]
            [certificaat.domain :as d]
            [certificaat.account :as account]
            [boot.core :as boot :refer [deftask with-pre-wrap]]
            [boot.util :as util]))

(deftask certificaat-setup
  "Certificaat setup. Will create the configuration directory and create the account keys."
  [c config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   t key-type KEY-TYPE kw "The key type, one of RSA or Elliptic Curve."
   s key-size KEY-SIZE int "Key length used to create the private key used to register the ACME account."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
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
        (do
          (log/info input)
          (util/info "Setting up configuration directories and creating keypairs.\n")))
      fileset)))

(deftask certificaat-request [i info INFO edn "The info map for the certificate request"]
  (with-pre-wrap fileset
    (util/info "Requesting certificate")
    (log/info info)
    fileset))

(deftask certificaat-challenge []
  (with-pre-wrap fileset
    (util/info "hello world")
    fileset))

(deftask certificaat-renew []
  (with-pre-wrap fileset
    (util/info "hello world")
    fileset))

(deftask certificaat-info []
  (with-pre-wrap fileset
    (util/info "hello world")
    fileset))
