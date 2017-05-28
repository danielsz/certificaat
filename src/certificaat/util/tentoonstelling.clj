(ns certificaat.util.tentoonstelling
  (:require [clojure.tools.logging :as log]
            [clojure.string :as str])
  (:import [javax.swing JOptionPane]
           [java.awt GraphicsEnvironment]
           [org.shredzone.acme4j.exception AcmeException]))


(defmulti show-tos (fn [title tos] (GraphicsEnvironment/isHeadless)))
(defmethod show-tos true [title tos] (println tos))
(defmethod show-tos false [title tos] (JOptionPane/showMessageDialog nil tos title JOptionPane/INFORMATION_MESSAGE))

(defmulti confirm-dialog (fn [title message] (GraphicsEnvironment/isHeadless)))
(defmethod confirm-dialog true [title message] (do (println message)
                                                   (println "Do you accept the terms? (Please type Yes or No)")
                                                   (let [option (read-line)]
                                                     (when (not= "yes" (str/lower-case option))
                                                       (throw (AcmeException. "User did not confirm"))))))
(defmethod confirm-dialog false [title message] (let [option (JOptionPane/showConfirmDialog nil message title JOptionPane/OK_CANCEL_OPTION)]
                                              (when (= option JOptionPane/CANCEL_OPTION)
                                                (throw (AcmeException. "User did not confirm")))))
