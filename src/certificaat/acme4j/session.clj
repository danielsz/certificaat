(ns certificaat.acme4j.session
  (:import [org.shredzone.acme4j Session]))

(defn create [acme-uri]
  (Session. acme-uri))

(defn login
  "Returns a login object"
  [session url-location keypair]
  (.login session url-location keypair))
