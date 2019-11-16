(ns certificaat.plugins.server
  (:require
   [certificaat.kung-fu :as k]
   [immutant.web :refer [run stop]]))

(def stop-server stop )

(defn handler [challenges]
  (fn [request]
    (loop [xs challenges]
      (if (= (:uri request) (str "/.well-known/acme-challenge/" (.getToken (first xs))))
        {:status 200
         :headers {"Content-Type" "text/plain"}
         :body (.getAuthorization (first xs))}
        (recur (rest xs))))))

(defn start-server [handler port]
  (let [server (run handler {:port port})]
    server))

(defn listen
  ([options]
   (let [challenges (k/get-challenges options)]
     (listen challenges options)))
  ([challenges {{{port :port enabled :enabled} :httpd} :plugins :as options}]
              (when enabled
                (let [handler (handler challenges)]
                  (start-server handler port)))))
