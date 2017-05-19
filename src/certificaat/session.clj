(ns certificaat.session
  (:require
   [certificaat.account :as account]
   [clojure.tools.logging :as log]
   [environ.core :refer [env]])
  (:import [org.shredzone.acme4j Session]))

(defn create
  ([] (let [keypair (account/load-from-disk)]
        (create keypair)))
  ([keypair] (let [session (Session. (:acme-uri env) keypair)]
               session)))


