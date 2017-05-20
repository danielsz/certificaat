(ns certificaat.authorization
  (:require [certificaat.registration :as registration]
            [certificaat.challenge :as challenge]
            [clojure.core.async :as a :refer [<!!]]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]]
            [certificaat.session :as session])
  (:import [org.shredzone.acme4j Authorization]
           [org.shredzone.acme4j.challenge Http01Challenge Dns01Challenge]))

(defn create
  ([] (let [domain (:certificaat-domain env)]
        (create domain)))
  ([domain] (let [reg (registration/create)
                  auth (.authorizeDomain reg domain)]
              (log/info "Authorization for domain" domain)
              auth)))

(defn delete [auth]
  (.deactivate auth))

#_ (defn restore []
     (Authorization/bind session (.getLocation auth)))

;(<!!  (challenge/accept challenge))
