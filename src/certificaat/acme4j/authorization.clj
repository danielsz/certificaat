(ns certificaat.acme4j.authorization
  (:require [clojure.core.async :as a :refer [<!!]]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]]
            [certificaat.domain :refer [Certificaat]]
            [certificaat.utils :refer [load-url]]
            [certificaat.acme4j.session :as session])
  (:import [org.shredzone.acme4j Authorization]
           [org.shredzone.acme4j.challenge Http01Challenge Dns01Challenge]
           org.shredzone.acme4j.Status
           org.shredzone.acme4j.exception.AcmeProtocolException))


(defn delete [auth]
  (.deactivate auth))

(defn restore [login path]
  (.bindAuthorization login (load-url path)))

(extend-type Authorization
  Certificaat
  (valid? [this]
    (let [status (try
                   (.getStatus this)
                   (catch AcmeProtocolException e (log/warn (.getMessage e))))]
      (log/debug "Authorization status:" status)
      (= Status/VALID status))) ; (.isBefore (.getExpires this) (Instant/now)))
  (pending? [this]
    (let [status (try
                   (.getStatus this)
                   (catch AcmeProtocolException e (log/warn (.getMessage e))))]
      (log/debug "Authorization status:" status)
      (= Status/PENDING status)))
  (marshal [this path]
    (spit path (.getLocation this)))) 
