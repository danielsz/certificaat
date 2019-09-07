(ns certificaat.acme4j.session
  (:require
   [certificaat.acme4j.account :as account]
   [clojure.tools.logging :as log]
   [environ.core :refer [env]])
  (:import [org.shredzone.acme4j Session]))

(defn create [acme-uri]
  (Session. acme-uri))

(defn login
  "Returns a login object"
  [session url-location keypair]
  (.login session url-location keypair))
