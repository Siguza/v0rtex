#import <UIKit/UIKit.h>

@interface MainController : UIViewController

@property(nonatomic, strong) UINavigationController *nav;

- (id)initWithNav:(UINavigationController*)nav;

@end
