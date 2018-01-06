(ns certificaat.acme4j.authorization
  (:require [clojure.core.async :as a :refer [<!!]]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]]
            [certificaat.domain :refer [Certificaat]]
            [certificaat.acme4j.session :as session])
  (:import [org.shredzone.acme4j Authorization]
           [org.shredzone.acme4j.challenge Http01Challenge Dns01Challenge]
           org.shredzone.acme4j.Status))

(defn create [domain reg]
  (let [auth (.authorizeDomain reg domain)]
    (log/info "Authorization for domain" domain)
    auth))

(defn delete [auth]
  (.deactivate auth))

(defn restore [session uri]
  (Authorization/bind session uri))

(extend-type Authorization
  Certificaat
  (valid? [this]
    (let [status (.getStatus this)]
      (log/info "Authorization status:" status)
      (or (= Status/VALID status) (= Status/PENDING status))))) ; (.isBefore (.getExpires this) (Instant/now)))
