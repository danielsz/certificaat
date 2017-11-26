(ns certificaat.domain
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.java.io :as io])
  (:import [java.net InetAddress]
           [java.net URI]))

(defn validate [spec val]
  (let [v (s/conform spec val)]
    (if (= v ::s/invalid)
      (throw (ex-info "Invalid options" (s/explain-data spec val)))
      v)))

(s/def ::path (s/and string? #(try (.exists (io/file %))
                                   (catch java.io.IOException e false))))
(s/def ::config-dir string?)
(s/def ::keypair-filename string?)
(s/def ::acme-uri (s/and string? #(.isAbsolute (URI. %))))
(s/def ::contact (s/and string? #(.isOpaque (URI. %))))
(s/def ::key-size #{1024 2048 4096})
(s/def ::key-type #{:rsa :ec})
(s/def ::domain (s/and string? #(try (.isReachable (InetAddress/getByName %) 5000)
                                     (catch java.io.IOException e false))))
(s/def ::san (s/coll-of ::domain :kind set?))
(s/def ::organisation string?)
(s/def ::challenge #{"http-01" "dns-01" "tls-sni-01" "tls-sni-02" "oob-01"})
(s/def ::challenges (s/coll-of ::challenge :kind set?))
(s/def ::challenge-uri #(re-matches #"challenge\..*\.\d+\.uri" %))
(s/def ::authorization-uri #(re-matches #"authorization\..*\.uri" %))
(s/def ::registration-uri #(re-matches #"registration.uri" %))
(s/def ::certificate-uri #(re-matches #"certificate.uri" %))


(s/def ::hook #{:before-challenge :after-request})
(s/def ::hooks (s/* ::hook))
(s/def ::plugins (s/keys :opt-un [::dhparams ::webroot ::email]))
(s/def ::enabled boolean?)

(s/def ::webroot (s/keys :req-un [::path ::enabled]))
(s/def ::dhparams (s/keys :req-un [::enabled]))
(s/def ::email (s/keys :req-un [::enabled]))

(s/def ::cli-actions #{"init" "run" "config" "reset" "info" "cron"})
(s/def ::cli-options (s/keys :req-un [::config-dir ::domain]))
(s/def ::config (s/keys :req-un [::acme-uri ::domain ::challenges ::contact ::plugins ::hooks]
                        :opt-un [::san]))

(defprotocol Certificaat
  (valid? [this]))

(def realms (-> (make-hierarchy)
                (derive :config-dir ::program)
                (derive :keypair-filename ::account)
                (derive :key-size ::account)
                (derive :key-type ::account)
                (derive :contact ::domain)
                (derive :acme-uri ::domain)
                (derive :domain ::domain)
                (derive :san ::domain)
                (derive :organisation ::domain)
                (derive :challenges ::domain)
                (derive :hooks ::domain)
                (derive :plugins ::account)))
