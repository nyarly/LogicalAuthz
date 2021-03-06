class Group < ActiveRecord::Base
  validates_presence_of :name
  validates_uniqueness_of :name
  
  has_many :permissions

  def self.member_class=(member_class)
    @member_class = member_class
    has_and_belongs_to_many :members, :class_name => member_class.name
  end

  # returns true if this group can do *action* on *controller* optional object
  def can?(action, controller, object = nil)
    conditions = {
      :group => self,
      :controller => controller,
      :action => action,
      :id => object.id
    }                   
    return GroupAuthz::is_authorized?(conditions)
  end
  
  class << self
    def admin_group
      self.find_by_name('Administration')
    end  

    attr_reader :member_class
  end

end
