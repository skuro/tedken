(defproject tedken "0.1.0-SNAPSHOT"
  :description "An implementation of the Encrypted Token pattern for CSRF protection"
  :url "http://skuro.tk"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [lock-key "1.1.0"]
                 [org.clojure/data.codec "0.1.0"]
                 [crypto-random "1.2.0"]
                 [simple-time "0.2.0"]]
  :profiles {:dev {:dependencies [[midje "1.5.1"]
                                  [environ "1.0.0"]]
                   :plugins [[lein-midje "3.1.3"]]
                   :env {:tedken.key "secret"}}})
