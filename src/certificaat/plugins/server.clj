(ns certificaat.plugins.server
  (:require [ring.adapter.jetty :refer [run-jetty]]))

(def handler
  (fn [content request]
    {:status 200
     :headers {"Content-Type" "text/plain"}
     :body content}))

(defn start-server [handler]
  (let [server (run-jetty handler {:port 80 :join? false})]
    server))

