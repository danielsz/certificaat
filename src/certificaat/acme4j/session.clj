(ns certificaat.acme4j.session
  (:require
   [certificaat.acme4j.account :as account]
   [clojure.tools.logging :as log]
   [environ.core :refer [env]])
  (:import [org.shredzone.acme4j Session]))

(defn create [keypair acme-uri]
  (let [session (Session. acme-uri keypair)]
    session))


