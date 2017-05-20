(ns certificaat.session
  (:require
   [certificaat.account :as account]
   [clojure.tools.logging :as log]
   [environ.core :refer [env]])
  (:import [org.shredzone.acme4j Session]))

(defn create
  ([] (let [keypair (account/load-from-disk)
            acme-uri (:acme-uri env)]
        (create keypair acme-uri)))
  ([keypair acme-uri] (let [session (Session. acme-uri keypair)]
                        session)))


