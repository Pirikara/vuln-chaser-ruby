require 'rails'

module Dummy
  class Application < Rails::Application
    config.eager_load = false
  end
end