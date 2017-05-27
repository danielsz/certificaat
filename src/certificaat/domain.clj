(ns certificaat.domain
  (:require [clojure.spec.alpha :as s])
  (:import [java.net InetAddress]
           [java.net URI]))

(defn validate [spec val]
  (let [v (s/conform spec val)]
    (if (= v ::s/invalid)
      (throw (ex-info "Invalid input" (s/explain-data spec val)))
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
(s/def ::certificaat-setup (s/keys :req-un [::config-dir ::keypair-filename ::domain ::key-size ::key-type]))
(s/def ::certificaat-authorize (s/keys :req-un [::config-dir ::keypair-filename ::domain ::challenges ::contact]))
(s/def ::certificaat-challenge (s/keys :req-un [::config-dir ::keypair-filename ::acme-uri]))
(s/def ::certificaat-request (s/keys :req-un [::config-dir ::keypair-filename ::acme-uri ::domain ::organisation ::contact]
                                     :opt-un [::san]))
(s/def ::certificaat-info (s/keys :req-un [::config-dir ::domain]))
