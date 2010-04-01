require 'group_authz_helper'

module GroupAuthz
  def self.is_authorized?(criteria={})
    criteria ||= {}

    controller_class = ::ApplicationController

    case criteria[:controller]
    when Class
      controller_class = criteria[:controller]
    when String, Symbol
      controller_class_name = criteria[:controller].to_s.camelize + "Controller"
      begin 
        controller_class = controller_class_name.constantize
      rescue NameError
      end
    end

    #TODO Fail if controller unspecified?

    criteria[:group] = criteria.has_key?(:group) ? [*criteria[:group]] : []
    if criteria.has_key?(:user)
      criteria[:group] += criteria[:user].groups
    end
    criteria[:groups] = criteria[:group]

    #TODO Fail if group unspecified and user unspecified?

    criteria[:action_aliases] = [*criteria[:action]].map do |action|
      controller_class.grant_aliases_for(action)
    end.flatten + [*criteria[:action]].map{|action| action.to_sym}

    controller_class.authorization_procs.each do |prok|
      approval = prok.call(criteria[:user], criteria) #Tempted to remove the user param
      next if approval == false
      next if approval.blank?
      return true
    end

    select_on = {
      :group_id => criteria[:group].map{|grp| grp.id},
      :controller => controller_class.controller_path,
      :action => nil,
      :subject_id => nil
    }

    return GroupAuthz::Permission.exists?(["controller = :controller AND group_id IN :group_ids AND
                                   ((action IS NULL AND id IS NULL) OR
                                    (action IN :action_names AND 
                                     (id IS NULL OR id = :subject_id)))",
                                     {
      :group_ids => criteria[:group].map {|grp| grp.id},
      :controller => controller_class.controller_path,
      :action_names => criteria[:action_aliases].map {|a| a.to_s},
      :subject_id => criteria[:id] }])
  end

  module Application
    def self.included(klass)
      klass.extend(ClassMethods)
    end
    include Helper

    def redirect_to_lobby(message = "You aren't authorized for that")
      flash[:error] = message
      begin
        redirect_to :back
      rescue ActionController::RedirectBackError
        redirect_to home_url
      end
    end

    def check_authorized
      current_user = AuthnFacade.current_user(self)
      return false if current_user.blank?

      criteria = {
        :user => current_user, 
        :controller => self.class,
        :action => action_name, 
        :id => params[:id]
      }

      if GroupAuthz.is_authorized?(criteria)
        flash[:group_authorization] = true
        return true
      else
        redirect_to_lobby("You are not authorized to perform this action.  Perhaps you need to log in?")
        flash[:group_authorization] = false
        return false
      end
    end

    module ClassMethods
      def needs_authorization(*actions)
        before_filter CheckAuthorization
        if actions.empty?
          write_inheritable_attribute(:whole_controller_authorization, true)
        else
          write_inheritable_array(:requires_action_authorization, actions)
        end
      end

      def grant_aliases(hash)
        aliases = read_inheritable_attribute(:grant_alias_hash) || Hash.new{|h,k| h[k] = []}
        hash.each_pair do |grant, allows|
          [*allows].each do |allowed|
            aliases[allowed.to_sym] << grant.to_sym
          end
        end
        write_inheritable_attribute(:grant_alias_hash, aliases)
      end
      
      def grant_aliases_for(action)
        grant_aliases = read_inheritable_attribute(:grant_alias_hash)

        if not grant_aliases.nil? and grant_aliases.has_key?(action)
          return grant_aliases[action]
        else
          return []
        end
      end

      def dynamic_authorization(&block)
        write_inheritable_array(:dynamic_authorization_procs, [proc &block])
      end

      def authorization_procs
        read_inheritable_attribute(:dynamic_authorization_procs) || []
      end

      def admin_authorized(*actions)
        actions.map!{|action| action.to_s}
        dynamic_authorization do |user, criteria|
          unless actions.nil? or actions.empty?
            return false unless actions.include?(criteria[:action].to_s)
          end
          return criteria[:group].include?(Group.admin_group)
        end
      end
    end

    class CheckAuthorization
      def self.filter(controller)
        if controller.class.read_inheritable_attribute(:whole_controller_authorization)
          return controller.check_authorized
        elsif (controller.class.read_inheritable_attribute(:requires_action_authorization) || []).include?(controller.action_name.to_sym)
          return controller.check_authorized
        else
          return true
        end
      end
    end
  end
end
