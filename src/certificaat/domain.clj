(ns certificaat.domain
  (:require [clojure.spec.alpha :as s]
            [clojure.java.io :as io])
  (:import [java.net InetAddress]
           [java.net URI]))

(defn validate [spec val]
  (let [v (s/conform spec val)]
    (if (= v ::s/invalid)
      (throw (ex-info "Invalid options" (s/explain-data spec val)))
      v)))

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

(s/def ::http-01-plugins #{"webroot" "server" "command"})
(s/def ::webroot (s/and string? #(try (.exists (io/file %))
                                      (catch java.io.IOException e false))))

(s/def ::command-line-actions #{"authorize" "request" "renew" "info" "plugin"})
(s/def ::certificaat-setup (s/keys :req-un [::config-dir ::keypair-filename ::domain ::key-size ::key-type]))
(s/def ::certificaat-authorize (s/keys :req-un [::config-dir ::keypair-filename ::acme-uri ::domain ::challenges ::contact]
                                       :opt-un [::san]))
(s/def ::certificaat-challenge (s/keys :req-un [::config-dir ::keypair-filename ::acme-uri]))
(s/def ::certificaat-request (s/keys :req-un [::config-dir ::keypair-filename ::acme-uri ::domain ::organisation ::contact]
                                     :opt-un [::san]))
(s/def ::certificaat-info (s/keys :req-un [::config-dir ::domain]))
(s/def ::certificaat-renew (s/keys :req-un [::config-dir ::keypair-filename ::acme-uri]))
(s/def ::certificaat-plugin (s/keys :req-un [::config-dir ::keypair-filename ::acme-uri ::webroot ::domain ]))

(def options (-> (make-hierarchy)
                 (derive ::config-dir ::program)
                 (derive ::keypair-filename ::account)
                 (derive ::acme-uri ::account)
                 (derive ::contact ::account)
                 (derive ::key-size ::account)
                 (derive ::key-type ::account)
                 (derive ::domain ::request)
                 (derive ::san ::request)
                 (derive ::organisation ::request)
                 (derive ::challenge ::request)
                 (derive ::challenges ::request)))
