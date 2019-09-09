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
    (log/debug "Authorization status:" (.getStatus this))
    (= Status/VALID (.getStatus this))) 
  (invalid? [this]
    (log/debug "Authorization status:" (.getStatus this))
    (= Status/INVALID (.getStatus this)))
  (pending? [this]
    (log/debug "Authorization status:" (.getStatus this))
    (= Status/PENDING (.getStatus this)))
  (deactivated? [this]
    (log/debug "Authorization status:" (.getStatus this))
    (= Status/DEACTIVATED (.getStatus this)))
  (expired? [this]
    (log/debug "Authorization status:" (.getStatus this))
    (= Status/EXPIRED (.getStatus this)))
  (revoked? [this]
    (log/debug "Authorization status:" (.getStatus this))
    (= Status/REVOKED (.getStatus this)))
  (marshal [this path]
    (spit path (.getLocation this))))
